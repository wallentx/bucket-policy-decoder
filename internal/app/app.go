package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/example/bucket-policy-decoder/internal/policy"
)

type Config struct {
	FilePath string
	Paste    bool
	RawJSON  string
}

func Run(cfg Config, stdin io.Reader, stdout, stderr io.Writer) error {
	sourceName, raw, err := readInput(cfg, stdin, stdout, stderr)
	if err != nil {
		return err
	}

	parsed, err := policy.Parse(raw)
	if err != nil {
		return err
	}
	color := shouldColorize(stdout)
	validation := policy.Validate(parsed)

	fmt.Fprintf(stdout, "Source: %s\n\n", sourceName)
	fmt.Fprint(stdout, validation.Render(color))
	fmt.Fprintln(stdout)
	fmt.Fprint(stdout, policy.RenderWithOptions(parsed, policy.RenderOptions{
		Color: color,
	}))
	if validation.HasErrors() {
		return policy.ErrValidationFailed
	}
	return nil
}

func shouldColorize(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	return policy.ShouldColorizeTerminalOutput(file)
}

func readInput(cfg Config, stdin io.Reader, stdout, stderr io.Writer) (string, []byte, error) {
	switch {
	case cfg.FilePath != "":
		data, err := policy.ReadFile(cfg.FilePath)
		if err != nil {
			return "", nil, err
		}
		return cfg.FilePath, data, nil
	case cfg.Paste:
		data, err := readPaste(stdin, stdout)
		if err != nil {
			return "", nil, err
		}
		return "pasted JSON", data, nil
	case cfg.RawJSON != "":
		return "inline JSON", []byte(cfg.RawJSON), nil
	default:
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(bytes.TrimSpace(data)) > 0 {
			return "stdin", data, nil
		}
		return interactiveInput(stdin, stdout, stderr)
	}
}

func interactiveInput(stdin io.Reader, stdout, stderr io.Writer) (string, []byte, error) {
	reader := bufio.NewReader(stdin)

	fmt.Fprintln(stdout, "Select input source:")
	fmt.Fprintln(stdout, "  1) Paste policy JSON")
	fmt.Fprintln(stdout, "  2) Read policy from file")
	fmt.Fprint(stdout, "> ")

	choice, err := reader.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("read selection: %w", err)
	}

	switch strings.TrimSpace(choice) {
	case "1":
		data, err := readPaste(reader, stdout)
		if err != nil {
			return "", nil, err
		}
		return "pasted JSON", data, nil
	case "2":
		fmt.Fprint(stdout, "File path: ")
		path, err := reader.ReadString('\n')
		if err != nil {
			return "", nil, fmt.Errorf("read file path: %w", err)
		}
		data, err := policy.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return "", nil, err
		}
		return strings.TrimSpace(path), data, nil
	default:
		return "", nil, errors.New("invalid selection")
	}
}

func readPaste(stdin io.Reader, stdout io.Writer) ([]byte, error) {
	fmt.Fprintln(stdout, "Paste the bucket policy JSON, then press Ctrl-D:")
	data, err := io.ReadAll(stdin)
	if err != nil {
		return nil, fmt.Errorf("read pasted JSON: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("no JSON received")
	}
	return data, nil
}
