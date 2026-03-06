package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/example/bucket-policy-decoder/internal/app"
)

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		printUsage(os.Stderr)
		os.Exit(2)
	}

	if err := app.Run(cfg, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (app.Config, error) {
	fs := flag.NewFlagSet("bucket-policy-decoder", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfg app.Config
	fs.StringVar(&cfg.FilePath, "file", "", "Path to a JSON bucket policy file")
	fs.BoolVar(&cfg.Paste, "paste", false, "Paste policy JSON directly into the terminal")
	fs.StringVar(&cfg.RawJSON, "json", "", "Raw bucket policy JSON")

	if err := fs.Parse(args); err != nil {
		return app.Config{}, err
	}
	if len(fs.Args()) > 0 {
		return app.Config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}

	selected := 0
	for _, ok := range []bool{
		cfg.FilePath != "",
		cfg.Paste,
		cfg.RawJSON != "",
	} {
		if ok {
			selected++
		}
	}
	if selected > 1 {
		return app.Config{}, errors.New("choose only one input source")
	}

	return cfg, nil
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  bucket-policy-decoder --file policy.json")
	fmt.Fprintln(w, "  bucket-policy-decoder --paste")
	fmt.Fprintln(w, "  bucket-policy-decoder --json '{...}'")
	fmt.Fprintln(w, "  cat policy.json | bucket-policy-decoder")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "If no input flag is given and stdin is a terminal, the tool starts in interactive mode.")
}
