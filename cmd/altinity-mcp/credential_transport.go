package main

import (
	"context"
	"fmt"
	"github.com/rs/zerolog/log"
	"net/http"
	"strings"
	"sync"

	"github.com/altinity/altinity-mcp/pkg/config"
	altinitymcp "github.com/altinity/altinity-mcp/pkg/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// withServerSnapshot captures the immutable parent and its converted tool rules
// together. Authentication, discovery and execution all use this generation.
func (a *application) withServerSnapshot(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.configMutex.RLock()
		parent := a.mcpServer
		a.configMutex.RUnlock()
		if parent == nil {
			http.Error(w, "Server unavailable", http.StatusServiceUnavailable)
			return
		}
		ctx := context.WithValue(r.Context(), altinitymcp.CHJWEServerKey, parent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *application) authenticateSnapshot(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parent := altinitymcp.GetClickHouseJWEServerFromContext(r.Context())
		cfg := parent.Config
		// Reuse OAuth challenges and expiry checks with a request-scoped adapter;
		// its auth injector cannot accidentally read a later global parent.
		if cfg.Server.OAuth.Enabled {
			adapter := &application{config: cfg, mcpServer: parent}
			adapter.createMCPAuthInjector(cfg)(next).ServeHTTP(w, r)
			return
		}
		if cfg.Server.JWE.Enabled {
			token, claims, _, _, err := parent.ValidateAuth(r)
			if err != nil || !parent.JWEClaimsHaveCredentials(claims) {
				http.Error(w, "Missing or invalid authentication token", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), altinitymcp.JWETokenKey, token)
			ctx = context.WithValue(ctx, altinitymcp.JWEClaimsKey, claims)
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func (a *application) buildSingleClusterHandler(cfg config.Config, sse bool) http.Handler {
	var sdkHandler http.Handler
	transport := ""
	if sse {
		transport = "sse"
		a.configMutex.Lock()
		pool := &credentialSSEPool{parent: a.mcpServer, buckets: make(map[string]*credentialSSEBucket)}
		a.ssePools = append(a.ssePools, pool)
		a.configMutex.Unlock()
		sdkHandler = pool
	} else {
		sdkHandler = mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
			return altinitymcp.GetClickHouseJWEServerFromContext(r.Context()).GetServer(r)
		}, statelessStreamableOptions())
	}
	mux := http.NewServeMux()
	openapiHandler := a.withServerSnapshot(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The reserved prefix can match /{token}/openapi when a tool itself is
		// named openapi. It carries no path credential; use the request headers.
		if strings.HasPrefix(r.URL.Path, "/openapi/") {
			r.SetPathValue("token", "")
		}
		parent := altinitymcp.GetClickHouseJWEServerFromContext(r.Context())
		parent.OpenAPIHandler(w, r)
	}))
	transportHandler := a.withServerSnapshot(a.authenticateSnapshot(sdkHandler))
	// /openapi/ and /{token}/openapi/ cannot coexist as Go mux patterns.
	// Combined mode reserves the pathless OpenAPI prefix in its fallback
	// instead, with the same authentication and body guards as explicit routes.
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cfg.Server.OpenAPI.Enabled && cfg.Server.JWE.Enabled && cfg.Server.OAuth.Enabled && strings.HasPrefix(r.URL.Path, "/openapi/") {
			openapiHandler.ServeHTTP(w, r)
			return
		}
		transportHandler.ServeHTTP(w, r)
	})
	for _, pattern := range transportRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled, transport) {
		mux.Handle(pattern, handler)
	}
	if cfg.Server.OpenAPI.Enabled {

		for _, pattern := range openAPIRoutePatterns(cfg.Server.JWE.Enabled, cfg.Server.OAuth.Enabled) {
			mux.Handle(pattern, openapiHandler)
		}

		if sse && cfg.Server.JWE.Enabled && cfg.Server.OAuth.Enabled {
			mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/openapi/") {
					openapiHandler.ServeHTTP(w, r)
					return
				}
				http.NotFound(w, r)
			}))
		}
		protocol := "http"
		if cfg.Server.OpenAPI.TLS {
			protocol = "https"
		}
		path := "/openapi"
		if cfg.Server.JWE.Enabled && !cfg.Server.OAuth.Enabled {
			path = "/{token}/openapi"
		}
		log.Info().Str("url", fmt.Sprintf("%s://%s:%d%s", protocol, cfg.Server.Address, cfg.Server.Port, path)).Msg("OpenAPI server listening")
	}
	mux.HandleFunc("/health", a.healthHandler)
	mux.HandleFunc("/livez", a.livenessHandler)
	mux.HandleFunc("/jwe-token-generator", a.jweTokenGeneratorHandler)
	a.registerOAuthHTTPRoutes(mux)
	return finalizeTransportHandler(mux, cfg)
}

// Each SDK SSE handler owns the sessions of one effective credential. The SDK
// invokes getServer only on GET and retains that GET's context for POST work.
// A POST must find its caller's existing bucket, and then its session inside
// that bucket; misses never allocate or discover anything.
type credentialSSEPool struct {
	mu      sync.Mutex
	parent  *altinitymcp.ClickHouseJWEServer
	buckets map[string]*credentialSSEBucket
	active  int
	closed  bool
}
type credentialSSEBucket struct {
	handler *mcp.SSEHandler
	refs    int
	cancels map[*http.Request]context.CancelFunc
}

func (p *credentialSSEPool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parent := altinitymcp.GetClickHouseJWEServerFromContext(r.Context())
	key := "static"
	if parent.Config.Server.JWE.Enabled || parent.Config.Server.OAuth.Enabled {
		var err error
		key, _, err = parent.CredentialCatalogKey(r.Context())
		if err != nil {
			http.Error(w, "Missing authentication", http.StatusUnauthorized)
			return
		}
	}
	p.mu.Lock()
	if p.closed || p.parent != parent {
		p.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	bucket := p.buckets[key]
	if r.Method != http.MethodGet {
		p.mu.Unlock()
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if bucket == nil {
			http.NotFound(w, r)
			return
		}
		bucket.handler.ServeHTTP(w, r)
		return
	}
	if bucket == nil {
		bucket = &credentialSSEBucket{handler: mcp.NewSSEHandler(parent.GetServer, nil), cancels: make(map[*http.Request]context.CancelFunc)}
		p.buckets[key] = bucket
	}
	ctx, cancel := context.WithCancel(r.Context())
	bucket.refs++
	bucket.cancels[r] = cancel
	p.active++
	p.mu.Unlock()
	defer func() {
		cancel()
		p.mu.Lock()
		delete(bucket.cancels, r)
		bucket.refs--
		p.active--
		if bucket.refs == 0 && p.buckets[key] == bucket {
			delete(p.buckets, key)
		}
		p.mu.Unlock()
	}()
	bucket.handler.ServeHTTP(w, r.WithContext(ctx))
}

func (p *credentialSSEPool) Retire(parent *altinitymcp.ClickHouseJWEServer) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, bucket := range p.buckets {
		for _, cancel := range bucket.cancels {
			cancel()
		}
	}
	p.buckets = make(map[string]*credentialSSEBucket)
	p.parent = parent
}
func (p *credentialSSEPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, bucket := range p.buckets {
		for _, cancel := range bucket.cancels {
			cancel()
		}
	}
	p.buckets = make(map[string]*credentialSSEBucket)
}
