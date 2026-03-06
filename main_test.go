package main

import "testing"

func TestParseFlagsAcceptsPositionalFilesAndShort(t *testing.T) {
	cfg, err := parseFlags([]string{"-s", "examples/*", "more.json"})
	if err != nil {
		t.Fatalf("parseFlags(-s positional files) error: %v", err)
	}

	if !cfg.ShortOnly {
		t.Errorf("cfg.ShortOnly = %v, want true", cfg.ShortOnly)
	}
	if len(cfg.FileArgs) != 2 {
		t.Fatalf("len(cfg.FileArgs) = %d, want 2", len(cfg.FileArgs))
	}
	if got, want := cfg.FileArgs[0], "examples/*"; got != want {
		t.Errorf("cfg.FileArgs[0] = %q, want %q", got, want)
	}
	if got, want := cfg.FileArgs[1], "more.json"; got != want {
		t.Errorf("cfg.FileArgs[1] = %q, want %q", got, want)
	}
}

func TestParseFlagsRejectsMixedFileAndJSONSources(t *testing.T) {
	_, err := parseFlags([]string{"--json", "{}", "policy.json"})
	if err == nil {
		t.Fatal("parseFlags(mixed sources) error = nil, want non-nil")
	}
}
