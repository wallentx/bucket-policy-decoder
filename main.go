package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/example/bucket-policy-decoder/internal/app"
)

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n\n", err)
		printUsage(os.Stderr)
		os.Exit(2)
	}

	if err := app.Run(cfg, os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (app.Config, error) {
	fs := flag.NewFlagSet("bucket-policy-decoder", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfg app.Config
	fs.BoolVar(&cfg.ShortOnly, "s", false, "Print only the plain-English reading")
	fs.BoolVar(&cfg.ShortOnly, "short", false, "Print only the plain-English reading")

	if err := fs.Parse(args); err != nil {
		return app.Config{}, err
	}
	cfg.FileArgs = append(cfg.FileArgs, fs.Args()...)

	return cfg, nil
}

func printUsage(w *os.File) {
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  bucket-policy-decoder policy.json")
	_, _ = fmt.Fprintln(w, "  bucket-policy-decoder s3://my-bucket")
	_, _ = fmt.Fprintln(w, "  bucket-policy-decoder -s examples/*")
	_, _ = fmt.Fprintln(w, "  cat policy.json | bucket-policy-decoder")
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintln(w, "If no input is given and stdin is a terminal, the tool starts in interactive mode.")
}
