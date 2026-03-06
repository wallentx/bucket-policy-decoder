package app

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/example/bucket-policy-decoder/internal/policy"
)

type Config struct {
	FilePath  string
	FileArgs  []string
	Paste     bool
	RawJSON   string
	ShortOnly bool
}

func Run(cfg Config, stdin io.Reader, stdout, stderr io.Writer) error {
	inputs, err := readInputs(cfg, stdin, stdout, stderr)
	if err != nil {
		return err
	}
	color := shouldColorize(stdout)
	stderrColor := shouldColorize(stderr)
	var validationFailed bool

	for idx, input := range inputs {
		parsed, err := policy.Parse(input.Raw)
		if err != nil {
			return fmt.Errorf("%s: %w", input.Name, err)
		}

		validation := policy.Validate(parsed)
		if cfg.ShortOnly {
			if idx > 0 {
				fmt.Fprintln(stdout)
			}
			fmt.Fprint(stdout, policy.RenderPlainEnglishWithOptions(parsed, policy.RenderOptions{
				Color: color,
			}))
			if validation.HasErrors() {
				validationFailed = true
				fmt.Fprintf(stderr, "Source: %s\n", input.Name)
				fmt.Fprint(stderr, validation.Render(stderrColor))
				fmt.Fprintln(stderr)
			}
			continue
		}

		if idx > 0 {
			fmt.Fprintln(stdout)
		}
		fmt.Fprintf(stdout, "Source: %s\n\n", input.Name)
		fmt.Fprint(stdout, validation.Render(color))
		fmt.Fprintln(stdout)
		fmt.Fprint(stdout, policy.RenderWithOptions(parsed, policy.RenderOptions{
			Color: color,
		}))
		if validation.HasErrors() {
			validationFailed = true
		}
	}
	if validationFailed {
		return policy.ErrValidationFailed
	}
	return nil
}

type inputDocument struct {
	Name string
	Raw  []byte
}

func shouldColorize(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	return policy.ShouldColorizeTerminalOutput(file)
}

func readInputs(cfg Config, stdin io.Reader, stdout, stderr io.Writer) ([]inputDocument, error) {
	switch {
	case cfg.FilePath != "" || len(cfg.FileArgs) > 0:
		paths, err := expandFileInputs(cfg.FilePath, cfg.FileArgs)
		if err != nil {
			return nil, err
		}
		inputs := make([]inputDocument, 0, len(paths))
		for _, path := range paths {
			data, err := policy.ReadFile(path)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, inputDocument{
				Name: path,
				Raw:  data,
			})
		}
		return inputs, nil
	case cfg.Paste:
		data, err := readPaste(stdin, stdout)
		if err != nil {
			return nil, err
		}
		return []inputDocument{{Name: "pasted JSON", Raw: data}}, nil
	case cfg.RawJSON != "":
		return []inputDocument{{Name: "inline JSON", Raw: []byte(cfg.RawJSON)}}, nil
	default:
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(bytes.TrimSpace(data)) > 0 {
			return []inputDocument{{Name: "stdin", Raw: data}}, nil
		}
		name, raw, err := interactiveInput(stdin, stdout, stderr)
		if err != nil {
			return nil, err
		}
		return []inputDocument{{Name: name, Raw: raw}}, nil
	}
}

func expandFileInputs(flagPath string, args []string) ([]string, error) {
	patterns := make([]string, 0, len(args)+1)
	if flagPath != "" {
		patterns = append(patterns, flagPath)
	}
	patterns = append(patterns, args...)

	var paths []string
	for _, pattern := range patterns {
		matches, err := expandFilePattern(pattern)
		if err != nil {
			return nil, err
		}
		paths = append(paths, matches...)
	}
	if len(paths) == 0 {
		return nil, errors.New("no input files matched")
	}
	return paths, nil
}

func expandFilePattern(pattern string) ([]string, error) {
	if pattern == "" {
		return nil, nil
	}

	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("expand %q: %w", pattern, err)
	}
	if len(matches) == 0 {
		if !hasGlobMeta(pattern) {
			return []string{pattern}, nil
		}
		return nil, fmt.Errorf("no files matched %q", pattern)
	}

	paths := make([]string, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			return nil, fmt.Errorf("stat %q: %w", match, err)
		}
		if info.IsDir() {
			continue
		}
		paths = append(paths, match)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no files matched %q", pattern)
	}
	return paths, nil
}

func hasGlobMeta(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
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
