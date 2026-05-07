package config

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/urfave/cli/v3"
)

// Command is the subset of urfave/cli/v3 *cli.Command that ApplyFlags needs.
// It mirrors the same interface used by overrideWithCLIFlags so the helper
// stays testable with a fake.
type Command interface {
	StringMap(name string) map[string]string
	String(name string) string
	StringSlice(name string) []string
	Int(name string) int
	Bool(name string) bool
	IsSet(name string) bool
}

// BuildFlags walks the given struct (typically &Config{}) and returns a
// []cli.Flag derived from `flag:`/`env:`/`desc:`/`default:` struct tags.
//
// Skips fields without a `flag:` tag, fields tagged `flag:"-"`, and
// nested struct fields without a `flag:` tag (the walk descends into them).
//
// Supported field types: string (incl. string-alias types like MCPTransport),
// bool, int, []string, map[string]string. Unsupported leaf types panic at
// build time so problems surface during `go test`, not at runtime.
func BuildFlags(cfg interface{}) []cli.Flag {
	var flags []cli.Flag
	walk(reflect.ValueOf(cfg), nil, func(field reflect.StructField, value reflect.Value) {
		flagName, ok := field.Tag.Lookup("flag")
		if !ok || flagName == "" || flagName == "-" {
			return
		}
		envVar := field.Tag.Get("env")
		desc := field.Tag.Get("desc")
		defaultStr := field.Tag.Get("default")
		flags = append(flags, makeFlag(flagName, envVar, desc, defaultStr, value))
	})
	return flags
}

// ApplyFlags walks cfg again and, for every leaf with a `flag:` tag,
// copies the CLI/env value into the struct when:
//   - cmd.IsSet(flagName) is true (user supplied the flag or env var), OR
//   - the current field value is the type's zero AND the `default:` tag is non-empty.
//
// This preserves the historical precedence: explicit CLI > YAML > hardcoded
// default.
func ApplyFlags(cfg interface{}, cmd Command) {
	walk(reflect.ValueOf(cfg), nil, func(field reflect.StructField, value reflect.Value) {
		flagName, ok := field.Tag.Lookup("flag")
		if !ok || flagName == "" || flagName == "-" {
			return
		}
		if !value.CanSet() {
			return
		}
		applyOne(flagName, field.Tag.Get("default"), value, cmd)
	})
}

// walk descends into nested structs via depth-first traversal and calls fn
// for every leaf (non-struct) field. cfg may be a pointer or a value; the
// pointer form is required to get settable values for ApplyFlags.
func walk(v reflect.Value, _ []string, fn func(reflect.StructField, reflect.Value)) {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		value := v.Field(i)
		if value.Kind() == reflect.Struct {
			walk(value, nil, fn)
			continue
		}
		fn(field, value)
	}
}

func makeFlag(flagName, envVar, desc, defaultStr string, value reflect.Value) cli.Flag {
	var sources cli.ValueSourceChain
	if envVar != "" {
		sources = cli.EnvVars(envVar)
	}
	switch value.Kind() {
	case reflect.String:
		return &cli.StringFlag{Name: flagName, Usage: desc, Value: defaultStr, Sources: sources}
	case reflect.Bool:
		var v bool
		if defaultStr != "" {
			parsed, err := strconv.ParseBool(defaultStr)
			if err != nil {
				panic(fmt.Sprintf("config: bad default for bool flag %s: %v", flagName, err))
			}
			v = parsed
		}
		return &cli.BoolFlag{Name: flagName, Usage: desc, Value: v, Sources: sources}
	case reflect.Int, reflect.Int64:
		var v int
		if defaultStr != "" {
			parsed, err := strconv.Atoi(defaultStr)
			if err != nil {
				panic(fmt.Sprintf("config: bad default for int flag %s: %v", flagName, err))
			}
			v = parsed
		}
		return &cli.IntFlag{Name: flagName, Usage: desc, Value: v, Sources: sources}
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.String {
			return &cli.StringSliceFlag{Name: flagName, Usage: desc, Sources: sources}
		}
	case reflect.Map:
		if value.Type().Key().Kind() == reflect.String && value.Type().Elem().Kind() == reflect.String {
			return &cli.StringMapFlag{Name: flagName, Usage: desc, Value: map[string]string{}, Sources: sources}
		}
	}
	panic(fmt.Sprintf("config: unsupported field type %s for flag %s", value.Type(), flagName))
}

func applyOne(flagName, defaultStr string, value reflect.Value, cmd Command) {
	switch value.Kind() {
	case reflect.String:
		switch {
		case cmd.IsSet(flagName):
			set := cmd.String(flagName)
			value.Set(reflect.ValueOf(set).Convert(value.Type()))
		case value.IsZero() && defaultStr != "":
			value.Set(reflect.ValueOf(defaultStr).Convert(value.Type()))
		}
	case reflect.Bool:
		if cmd.IsSet(flagName) {
			value.SetBool(cmd.Bool(flagName))
		}
		// bool defaults baked into the cli.Flag default — no zero-fill needed.
	case reflect.Int, reflect.Int64:
		switch {
		case cmd.IsSet(flagName):
			value.SetInt(int64(cmd.Int(flagName)))
		case value.IsZero() && defaultStr != "":
			parsed, err := strconv.Atoi(defaultStr)
			if err == nil {
				value.SetInt(int64(parsed))
			}
		}
	case reflect.Slice:
		if value.Type().Elem().Kind() != reflect.String {
			return
		}
		if cmd.IsSet(flagName) {
			value.Set(reflect.ValueOf(cmd.StringSlice(flagName)))
		}
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String || value.Type().Elem().Kind() != reflect.String {
			return
		}
		if m := cmd.StringMap(flagName); len(m) > 0 {
			value.Set(reflect.ValueOf(m))
		}
	}
}
