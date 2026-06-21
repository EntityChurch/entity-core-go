package main

import (
	"reflect"
	"testing"
)

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		// Basic.
		{"ls", []string{"ls"}},
		{"cat foo", []string{"cat", "foo"}},
		{"connect go 127.0.0.1:9002", []string{"connect", "go", "127.0.0.1:9002"}},

		// Multiple spaces/tabs.
		{"ls   foo", []string{"ls", "foo"}},
		{"ls\tfoo", []string{"ls", "foo"}},
		{"  ls  ", []string{"ls"}},

		// Quoted strings.
		{`cat "path with spaces"`, []string{"cat", "path with spaces"}},
		{`cat 'single quoted'`, []string{"cat", "single quoted"}},
		{`exec handler op "resource target"`, []string{"exec", "handler", "op", "resource target"}},

		// Empty.
		{"", nil},
		{"   ", nil},

		// Unclosed quotes — includes partial token.
		{`cat "unclosed`, []string{"cat", "unclosed"}},

		// Adjacent quotes.
		{`"a""b"`, []string{"ab"}},
	}

	for _, tt := range tests {
		got := splitArgs(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("splitArgs(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestClassifyEntry(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want string
	}{
		{
			"directory only",
			map[interface{}]interface{}{"has_children": true, "hash": nil},
			"dir",
		},
		{
			"entity only",
			map[interface{}]interface{}{"has_children": false, "hash": []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}},
			"entity",
		},
		{
			"dir+entity",
			map[interface{}]interface{}{"has_children": true, "hash": []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}},
			"dir+entity",
		},
		{
			"nil value",
			nil,
			"",
		},
		{
			"wrong map type",
			map[string]interface{}{"has_children": true},
			"",
		},
		{
			"no fields",
			map[interface{}]interface{}{},
			"",
		},
	}

	for _, tt := range tests {
		got := classifyEntry(tt.val)
		if got != tt.want {
			t.Errorf("classifyEntry(%s) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestPrompt(t *testing.T) {
	sh := NewShell("")

	// At root.
	if got := sh.prompt(); got != "entity:/ > " {
		t.Errorf("root prompt = %q, want %q", got, "entity:/ > ")
	}

	// Simulate a connection.
	sh.conns["go"] = &PeerConn{Alias: "go", PeerID: "abc123"}
	sh.peerMap["abc123"] = "go"

	// At peer root.
	sh.wd = "/abc123/"
	if got := sh.prompt(); got != "entity:go:/ > " {
		t.Errorf("peer root prompt = %q, want %q", got, "entity:go:/ > ")
	}

	// Inside peer tree.
	sh.wd = "/abc123/system/handler/"
	if got := sh.prompt(); got != "entity:go:/system/handler/ > " {
		t.Errorf("peer path prompt = %q, want %q", got, "entity:go:/system/handler/ > ")
	}

	// At entity (no trailing slash).
	sh.wd = "/abc123/system/handler/tree"
	if got := sh.prompt(); got != "entity:go:/system/handler/tree > " {
		t.Errorf("entity prompt = %q, want %q", got, "entity:go:/system/handler/tree > ")
	}
}
