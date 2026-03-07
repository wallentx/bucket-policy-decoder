package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/example/bucket-policy-decoder/internal/policy"
)

type Config struct {
	FileArgs  []string
	ShortOnly bool
}

type analyzedDocument struct {
	Input      inputDocument
	Parsed     policy.Policy
	Validation policy.ValidationResult
}

func Run(cfg Config, stdin io.Reader, stdout, stderr io.Writer) error {
	if shouldStartInteractiveEditor(cfg, stdin, stdout) {
		validationFailed, err := runEditorTUI(stdin, stdout, shouldColorize(stdout))
		if err != nil {
			return err
		}
		if validationFailed {
			return policy.ErrValidationFailed
		}
		return nil
	}

	inputs, err := readInputs(cfg, stdin, stdout, stderr)
	if err != nil {
		return err
	}
	color := shouldColorize(stdout)
	stderrColor := shouldColorize(stderr)
	documents, validationFailed, err := analyzeInputs(inputs)
	if err != nil {
		return err
	}

	switch {
	case cfg.ShortOnly:
		renderShort(documents, stdout, stderr, color, stderrColor)
	case supportsTUI(stdin, stdout):
		if err := runTUI(documents, stdin, stdout, color); err != nil {
			return err
		}
	default:
		renderStatic(documents, stdout, color)
	}

	if validationFailed {
		return policy.ErrValidationFailed
	}
	return nil
}

func shouldStartInteractiveEditor(cfg Config, stdin io.Reader, stdout io.Writer) bool {
	if cfg.ShortOnly {
		return false
	}
	if len(cfg.FileArgs) > 0 {
		return false
	}
	return supportsTUI(stdin, stdout)
}

func analyzeInputs(inputs []inputDocument) ([]analyzedDocument, bool, error) {
	documents := make([]analyzedDocument, 0, len(inputs))
	var validationFailed bool

	for _, input := range inputs {
		parsed, err := policy.Parse(input.Raw)
		if err != nil {
			return nil, false, fmt.Errorf("%s: %w", input.Name, err)
		}

		validation := policy.Validate(parsed)
		validation.Merge(validatePolicyWithAWS(context.Background(), input.Raw))
		if validation.HasErrors() {
			validationFailed = true
		}

		documents = append(documents, analyzedDocument{
			Input:      input,
			Parsed:     parsed,
			Validation: validation,
		})
	}

	return documents, validationFailed, nil
}

func renderShort(documents []analyzedDocument, stdout, stderr io.Writer, stdoutColor, stderrColor bool) {
	var wroteIssues bool

	for idx, document := range documents {
		if idx > 0 {
			_, _ = fmt.Fprintln(stdout)
		}
		if document.Input.ShowNameInShort {
			_, _ = fmt.Fprintln(stdout, styleShortFilename(document.Input.Name, stdoutColor))
		}
		_, _ = fmt.Fprint(stdout, policy.RenderPlainEnglishWithOptions(document.Parsed, policy.RenderOptions{
			Color: stdoutColor,
		}))

		if len(document.Validation.Findings) == 0 {
			continue
		}
		if wroteIssues {
			_, _ = fmt.Fprintln(stderr)
		}
		wroteIssues = true
		if document.Input.Name != "" {
			_, _ = fmt.Fprintln(stderr, styleShortFilename(document.Input.Name, stderrColor))
		}
		_, _ = fmt.Fprint(stderr, document.Validation.Render(stderrColor))
	}
}

func renderStatic(documents []analyzedDocument, stdout io.Writer, color bool) {
	for idx, document := range documents {
		if idx > 0 {
			_, _ = fmt.Fprintln(stdout)
		}
		_, _ = fmt.Fprintf(stdout, "Source: %s\n\n", document.Input.Name)
		if len(document.Validation.Findings) > 0 {
			_, _ = fmt.Fprint(stdout, document.Validation.Render(color))
			_, _ = fmt.Fprintln(stdout)
		}
		_, _ = fmt.Fprint(stdout, policy.RenderWithOptions(document.Parsed, policy.RenderOptions{
			Color: color,
		}))
	}
}

type inputDocument struct {
	Name            string
	Raw             []byte
	ShowNameInShort bool
}

var fetchS3Policy = fetchBucketPolicyFromS3
var validatePolicyWithAWS = validatePolicyWithAccessAnalyzer

func shouldColorize(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	return policy.ShouldColorizeTerminalOutput(file)
}

func readInputs(cfg Config, stdin io.Reader, stdout, stderr io.Writer) ([]inputDocument, error) {
	switch {
	case len(cfg.FileArgs) > 0:
		paths, err := expandInputPatterns(cfg.FileArgs)
		if err != nil {
			return nil, err
		}
		return readPathInputs(paths)
	default:
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read stdin: %w", err)
		}
		if len(bytes.TrimSpace(data)) > 0 {
			return []inputDocument{{Name: "stdin", Raw: data}}, nil
		}
		return nil, errors.New("no input provided")
	}
}

func styleShortFilename(name string, color bool) string {
	if !color || name == "" {
		return name
	}
	return "\x1b[38;5;141m" + name + "\x1b[0m"
}

func expandInputPatterns(patterns []string) ([]string, error) {
	var paths []string
	for _, pattern := range patterns {
		if isS3Reference(pattern) {
			paths = append(paths, pattern)
			continue
		}
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

func readPathInputs(refs []string) ([]inputDocument, error) {
	inputs := make([]inputDocument, 0, len(refs))
	for _, ref := range refs {
		if isS3Reference(ref) {
			data, err := fetchS3Policy(context.Background(), ref)
			if err != nil {
				return nil, err
			}
			inputs = append(inputs, inputDocument{
				Name:            ref,
				Raw:             data,
				ShowNameInShort: true,
			})
			continue
		}

		data, err := policy.ReadFile(ref)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, inputDocument{
			Name:            ref,
			Raw:             data,
			ShowNameInShort: true,
		})
	}
	return inputs, nil
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

func isS3Reference(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "s3://")
}

func parseS3Reference(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "s3://") {
		return "", fmt.Errorf("invalid s3 reference %q", ref)
	}

	target := strings.TrimPrefix(ref, "s3://")
	bucket, _, _ := strings.Cut(target, "/")
	if bucket == "" {
		return "", fmt.Errorf("invalid s3 reference %q", ref)
	}
	return bucket, nil
}

func fetchBucketPolicyFromS3(ctx context.Context, ref string) ([]byte, error) {
	bucket, err := parseS3Reference(ref)
	if err != nil {
		return nil, err
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}

	client := s3.NewFromConfig(cfg)
	output, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		return nil, err
	}
	if output.Policy == nil || strings.TrimSpace(*output.Policy) == "" {
		return nil, fmt.Errorf("bucket %q returned an empty policy", bucket)
	}
	return []byte(*output.Policy), nil
}

func validatePolicyWithAccessAnalyzer(ctx context.Context, raw []byte) policy.ValidationResult {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return policy.ValidationResult{}
	}
	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return policy.ValidationResult{}
	}

	client := accessanalyzer.NewFromConfig(cfg)
	paginator := accessanalyzer.NewValidatePolicyPaginator(client, &accessanalyzer.ValidatePolicyInput{
		PolicyDocument:             aws.String(string(raw)),
		PolicyType:                 accessanalyzertypes.PolicyTypeResourcePolicy,
		ValidatePolicyResourceType: accessanalyzertypes.ValidatePolicyResourceTypeS3Bucket,
	})

	result := policy.ValidationResult{UsedAWS: true}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return policy.ValidationResult{}
		}
		for _, finding := range page.Findings {
			if shouldIgnoreAccessAnalyzerFinding(finding) {
				continue
			}
			result.Findings = append(result.Findings, policy.Finding{
				Severity: mapAccessAnalyzerSeverity(finding.FindingType),
				Path:     "AWS.AccessAnalyzer",
				Message:  formatAccessAnalyzerFinding(finding),
			})
		}
	}

	return result
}

func shouldIgnoreAccessAnalyzerFinding(finding accessanalyzertypes.ValidatePolicyFinding) bool {
	return aws.ToString(finding.IssueCode) == "EMPTY_SID_VALUE"
}

func mapAccessAnalyzerSeverity(kind accessanalyzertypes.ValidatePolicyFindingType) policy.Severity {
	switch kind {
	case accessanalyzertypes.ValidatePolicyFindingTypeError:
		return policy.SeverityError
	default:
		return policy.SeverityWarning
	}
}

func formatAccessAnalyzerFinding(finding accessanalyzertypes.ValidatePolicyFinding) string {
	details := aws.ToString(finding.FindingDetails)
	issueCode := aws.ToString(finding.IssueCode)
	if issueCode == "" {
		return details
	}
	if details == "" {
		return issueCode
	}
	return issueCode + ": " + details
}
