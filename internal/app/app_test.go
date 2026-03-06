package app

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunShortModePrintsFileNames(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")

	if err := os.WriteFile(first, []byte(`{
		"Version":"2012-10-17",
		"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::demo/*"}]
	}`), 0o644); err != nil {
		t.Fatalf("os.WriteFile(first) error: %v", err)
	}
	if err := os.WriteFile(second, []byte(`{
		"Version":"2012-10-17",
		"Statement":[
			{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"},
			{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::demo"}
		]
	}`), 0o644); err != nil {
		t.Fatalf("os.WriteFile(second) error: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(Config{
		FileArgs:  []string{first, second},
		ShortOnly: true,
	}, strings.NewReader(""), &stdout, &stderr)
	if err != nil {
		t.Fatalf("Run(short files) error: %v", err)
	}

	got := stdout.String()
	wantParts := []string{
		first + "\n1. It prevents everyone from being able to upload objects to bucket demo.\n",
		"\n" + second + "\n1. It allows everyone to read/download objects from bucket demo.\n2. It allows everyone to list bucket demo.\n",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Errorf("Run(short files) missing %q\nfull output:\n%s", want, got)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestStyleShortFilenameColor(t *testing.T) {
	got := styleShortFilename("examples/foo.json", true)
	want := "\x1b[38;5;141mexamples/foo.json\x1b[0m"
	if got != want {
		t.Errorf("styleShortFilename(color) = %q, want %q", got, want)
	}
}
