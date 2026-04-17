package server

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	chparser "github.com/AfterShip/clickhouse-sql-parser/parser"
)

var singleLineCommentRE = regexp.MustCompile(`(?m)--.*$`)
var multiLineCommentRE = regexp.MustCompile(`/\*[\s\S]*?\*/`)

func isSelectQuery(query string) bool {
	query = multiLineCommentRE.ReplaceAllString(query, "")
	query = singleLineCommentRE.ReplaceAllString(query, "")
	trimmed := strings.TrimSpace(strings.ToUpper(query))
	return strings.HasPrefix(trimmed, "SELECT") || strings.HasPrefix(trimmed, "WITH") || strings.HasPrefix(trimmed, "SHOW") || strings.HasPrefix(trimmed, "DESC") || strings.HasPrefix(trimmed, "EXISTS") || strings.HasPrefix(trimmed, "EXPLAIN")
}

func hasLimitClause(query string) bool {
	hasLimit, _ := regexp.MatchString(`(?im)limit\s+\d+`, query)
	return hasLimit
}

// NormalizeBlockedClauses converts a list of clause names into a normalized
// set (upper-cased). Returns nil for empty input.
func NormalizeBlockedClauses(clauses []string) map[string]bool {
	if len(clauses) == 0 {
		return nil
	}
	set := make(map[string]bool, len(clauses))
	for _, name := range clauses {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		set[strings.ToUpper(trimmed)] = true
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// checkBlockedClauses parses the query with the ClickHouse SQL AST parser and
// checks whether it contains any blocked clauses. If parsing fails, the query
// is rejected (no heuristic fallback): the parser must understand the SQL
// before clause blocking can be applied safely.
func checkBlockedClauses(query string, blocked map[string]bool) (blockedClause string, err error) {
	if len(blocked) == 0 {
		return "", nil
	}

	p := chparser.NewParser(query)
	stmts, parseErr := p.ParseStmts()
	if parseErr != nil {
		return "", fmt.Errorf("SQL could not be parsed for blocked-clause validation: %w", parseErr)
	}

	for _, stmt := range stmts {
		if name := findBlockedClauseInAST(stmt, blocked); name != "" {
			return name, nil
		}
	}
	return "", nil
}

// blockedASTStructuralMatchers cover SQL constructs that are not represented
// by a dedicated AST type whose Go name maps cleanly to a single keyword (see
// astTypeNamesForBlockedLookup). Add rows here only for those cases; everything
// else is derived from concrete *parser types during the walk (e.g. WhereClause
// → WHERE, SettingsClause → SETTINGS).
var blockedASTStructuralMatchers = []struct {
	name  string
	match func(n chparser.Expr) bool
}{
	{
		name: "INTO OUTFILE",
		match: func(n chparser.Expr) bool {
			s, ok := n.(*chparser.ShowStmt)
			return ok && s.OutFile != nil
		},
	},
}

// astTypeNamesForBlockedLookup maps a concrete AST struct name from
// github.com/AfterShip/clickhouse-sql-parser to config keys operators may list
// in blocked_query_clauses (compared case-insensitively; stored upper-case).
//
// Examples: SettingsClause→SETTINGS, SetStmt→SET, SelectQuery→SELECT, FormatClause→FORMAT.
// The full type name (e.g. SETTINGSCLAUSE) is also accepted.
func astTypeNamesForBlockedLookup(typeName string) []string {
	if typeName == "" {
		return nil
	}
	u := strings.ToUpper(typeName)
	var out []string
	switch {
	case strings.HasSuffix(typeName, "Clause"):
		out = append(out, strings.ToUpper(strings.TrimSuffix(typeName, "Clause")))
		out = append(out, u)
	case strings.HasSuffix(typeName, "Stmt"):
		out = append(out, strings.ToUpper(strings.TrimSuffix(typeName, "Stmt")))
		out = append(out, u)
	case strings.HasSuffix(typeName, "Query"):
		out = append(out, strings.ToUpper(strings.TrimSuffix(typeName, "Query")))
		out = append(out, u)
	default:
		out = append(out, u)
	}
	return out
}

func matchBlockedClauseAtNode(n chparser.Expr, blocked map[string]bool) string {
	if n == nil {
		return ""
	}
	for _, m := range blockedASTStructuralMatchers {
		if blocked[m.name] && m.match(n) {
			return m.name
		}
	}
	rv := reflect.ValueOf(n)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return ""
	}
	for _, key := range astTypeNamesForBlockedLookup(rv.Elem().Type().Name()) {
		if blocked[key] {
			return key
		}
	}
	return ""
}

// findBlockedClauseInAST walks the tree and returns the first blocked name that
// matches a structural rule or an AST concrete type (via reflection).
func findBlockedClauseInAST(root chparser.Expr, blocked map[string]bool) string {
	var found string
	chparser.Walk(root, func(n chparser.Expr) bool {
		if found != "" {
			return false
		}
		if name := matchBlockedClauseAtNode(n, blocked); name != "" {
			found = name
			return false
		}
		return true
	})
	return found
}
