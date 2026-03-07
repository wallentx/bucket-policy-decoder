package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	accessanalyzertypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	"github.com/example/bucket-policy-decoder/internal/policy"
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

func TestReadPathInputsFetchesS3References(t *testing.T) {
	originalFetch := fetchS3Policy
	t.Cleanup(func() {
		fetchS3Policy = originalFetch
	})

	fetchS3Policy = func(ctx context.Context, ref string) ([]byte, error) {
		if got, want := ref, "s3://demo-bucket/path"; got != want {
			t.Fatalf("fetchS3Policy ref = %q, want %q", got, want)
		}
		return []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo-bucket/*"}]}`), nil
	}

	inputs, err := readPathInputs([]string{"s3://demo-bucket/path"})
	if err != nil {
		t.Fatalf("readPathInputs(s3 ref) error: %v", err)
	}
	if len(inputs) != 1 {
		t.Fatalf("len(inputs) = %d, want 1", len(inputs))
	}
	if got, want := inputs[0].Name, "s3://demo-bucket/path"; got != want {
		t.Errorf("inputs[0].Name = %q, want %q", got, want)
	}
	if !inputs[0].ShowNameInShort {
		t.Errorf("inputs[0].ShowNameInShort = %v, want true", inputs[0].ShowNameInShort)
	}
}

func TestRunIncludesAWSValidationFindings(t *testing.T) {
	originalValidate := validatePolicyWithAWS
	t.Cleanup(func() {
		validatePolicyWithAWS = originalValidate
	})

	validatePolicyWithAWS = func(ctx context.Context, raw []byte) policy.ValidationResult {
		return policy.ValidationResult{
			UsedAWS: true,
			Findings: []policy.Finding{
				{
					Severity: policy.SeverityWarning,
					Path:     "AWS.AccessAnalyzer",
					Message:  "TEST_FINDING: example AWS finding",
				},
			},
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(
		Config{},
		strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}`),
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("Run(aws validation) error: %v", err)
	}

	got := stdout.String()
	if !strings.Contains(got, "AWS.AccessAnalyzer: TEST_FINDING: example AWS finding") {
		t.Errorf("Run(aws validation) missing AWS finding\nfull output:\n%s", got)
	}
}

func TestRunShortModePrintsWarningsToStderr(t *testing.T) {
	originalValidate := validatePolicyWithAWS
	t.Cleanup(func() {
		validatePolicyWithAWS = originalValidate
	})

	validatePolicyWithAWS = func(ctx context.Context, raw []byte) policy.ValidationResult {
		return policy.ValidationResult{
			UsedAWS: true,
			Findings: []policy.Finding{
				{
					Severity: policy.SeverityWarning,
					Path:     "AWS.AccessAnalyzer",
					Message:  "example warning",
				},
			},
		}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(
		Config{ShortOnly: true},
		strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}`),
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("Run(short warning) error: %v", err)
	}

	if !strings.Contains(stdout.String(), "1. It allows everyone to read/download objects from bucket demo.") {
		t.Errorf("stdout missing short output\nfull output:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "AWS.AccessAnalyzer: example warning") {
		t.Errorf("stderr missing warning output\nfull output:\n%s", stderr.String())
	}
}

func TestRunOmitsIssueBannerWhenPolicyIsClean(t *testing.T) {
	originalValidate := validatePolicyWithAWS
	t.Cleanup(func() {
		validatePolicyWithAWS = originalValidate
	})

	validatePolicyWithAWS = func(ctx context.Context, raw []byte) policy.ValidationResult {
		return policy.ValidationResult{}
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	err := Run(
		Config{},
		strings.NewReader(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}`),
		&stdout,
		&stderr,
	)
	if err != nil {
		t.Fatalf("Run(clean policy) error: %v", err)
	}

	if strings.Contains(stdout.String(), "Validation:") || strings.Contains(stdout.String(), "Issues:") {
		t.Errorf("stdout unexpectedly mentioned validation\nfull output:\n%s", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

func TestDecodeDraftSwitchesEditorToViewMode(t *testing.T) {
	originalValidate := validatePolicyWithAWS
	t.Cleanup(func() {
		validatePolicyWithAWS = originalValidate
	})
	validatePolicyWithAWS = func(ctx context.Context, raw []byte) policy.ValidationResult {
		return policy.ValidationResult{}
	}

	model := newEditorTUIModel(false)
	model.insertDraftText(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::demo/*"}]}`)
	model.decodeDraft()

	if model.Mode != tuiModeView {
		t.Fatalf("model.Mode = %q, want %q", model.Mode, tuiModeView)
	}
	if len(model.Documents) != 1 {
		t.Fatalf("len(model.Documents) = %d, want 1", len(model.Documents))
	}
	if model.ValidationFailed {
		t.Fatal("model.ValidationFailed = true, want false")
	}
}

func TestDecodeDraftKeepsEditorModeOnParseError(t *testing.T) {
	model := newEditorTUIModel(false)
	model.insertDraftText(`{"Version":"2012-10-17"`)
	model.decodeDraft()

	if model.Mode != tuiModeEdit {
		t.Fatalf("model.Mode = %q, want %q", model.Mode, tuiModeEdit)
	}
	if !model.DraftStatusError {
		t.Fatal("model.DraftStatusError = false, want true")
	}
	if model.DraftStatus == "" {
		t.Fatal("model.DraftStatus = empty, want parse error message")
	}
}

func TestShouldIgnoreAccessAnalyzerFinding(t *testing.T) {
	if !shouldIgnoreAccessAnalyzerFinding(accessanalyzertypes.ValidatePolicyFinding{
		IssueCode: aws.String("EMPTY_SID_VALUE"),
	}) {
		t.Fatal("shouldIgnoreAccessAnalyzerFinding did not ignore EMPTY_SID_VALUE")
	}

	if shouldIgnoreAccessAnalyzerFinding(accessanalyzertypes.ValidatePolicyFinding{
		IssueCode: aws.String("PASS_ROLE_WITH_STAR_IN_ACTION_AND_RESOURCE"),
	}) {
		t.Fatal("shouldIgnoreAccessAnalyzerFinding ignored an unrelated issue")
	}
}

func TestFindingsForStatementIncludesGlobalAndMatchingStatementOnly(t *testing.T) {
	validation := policy.ValidationResult{
		Findings: []policy.Finding{
			{Severity: policy.SeverityWarning, Path: "AWS.AccessAnalyzer", Message: "global"},
			{Severity: policy.SeverityWarning, Path: "Statement[0].Action[0]", Message: "first"},
			{Severity: policy.SeverityError, Path: "Statement[1].Effect", Message: "second"},
		},
	}

	got := findingsForStatement(validation, 1)
	if len(got) != 2 {
		t.Fatalf("len(findingsForStatement) = %d, want 2", len(got))
	}
	if got[0].Message != "global" {
		t.Errorf("got[0].Message = %q, want global", got[0].Message)
	}
	if got[1].Message != "second" {
		t.Errorf("got[1].Message = %q, want second", got[1].Message)
	}
}

func TestRenderDetailPaneShowsSelectedStatementAndIssues(t *testing.T) {
	document := tuiDocument{
		Document: analyzedDocument{
			Input: inputDocument{Name: "examples/demo.json"},
			Parsed: policy.Policy{
				Version: "2012-10-17",
				Statement: policy.Statements{
					{
						Effect:    "Allow",
						Principal: policy.PrincipalValue{Any: true},
						Action:    policy.StringList{"s3:GetObject"},
						Resource:  policy.StringList{"arn:aws:s3:::demo/*"},
					},
					{
						Effect:    "Deny",
						Principal: policy.PrincipalValue{Any: true},
						Action:    policy.StringList{"s3:PutObject"},
						Resource:  policy.StringList{"arn:aws:s3:::demo/*"},
					},
				},
			},
			Validation: policy.ValidationResult{
				Findings: []policy.Finding{
					{Severity: policy.SeverityWarning, Path: "AWS.AccessAnalyzer", Message: "global"},
					{Severity: policy.SeverityError, Path: "Statement[1].Effect", Message: "selected"},
				},
			},
		},
	}

	got := strings.Join(renderDetailPane(document, 1, 90, 10, false), "\n")
	wantParts := []string{
		"It prevents everyone from being able to upload objects to bucket demo.",
		"ERROR Statement[1].Effect: selected",
		"WARNING AWS.AccessAnalyzer: global",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Errorf("renderDetailPane missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestRenderPolicyPaneMarksSelectedStatementWithGutter(t *testing.T) {
	document := tuiDocument{
		Document: analyzedDocument{
			Input: inputDocument{Name: "examples/demo.json"},
			Parsed: policy.Policy{
				Version: "2012-10-17",
				Statement: policy.Statements{
					{
						SID:       "One",
						Effect:    "Allow",
						Principal: policy.PrincipalValue{Any: true},
						Action:    policy.StringList{"s3:GetObject"},
						Resource:  policy.StringList{"arn:aws:s3:::demo/*"},
					},
				},
			},
		},
	}
	document.JSONView = buildFallbackPolicyJSONView(document.Document.Parsed)

	lines := renderPolicyPane(document, 0, 80, 8, false)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "> ") {
		t.Fatalf("renderPolicyPane did not mark selected statement\nfull output:\n%s", joined)
	}
}

func TestRenderPolicyPaneHighlightsSelectedStatementWhenColorEnabled(t *testing.T) {
	document := tuiDocument{
		Document: analyzedDocument{
			Input: inputDocument{Name: "examples/demo.json"},
			Parsed: policy.Policy{
				Version: "2012-10-17",
				Statement: policy.Statements{
					{
						SID:       "One",
						Effect:    "Allow",
						Principal: policy.PrincipalValue{Any: true},
						Action:    policy.StringList{"s3:GetObject"},
						Resource:  policy.StringList{"arn:aws:s3:::demo/*"},
					},
				},
			},
		},
	}
	document.JSONView = buildFallbackPolicyJSONView(document.Document.Parsed)

	lines := renderPolicyPane(document, 0, 80, 8, true)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "\x1b[48;5;236m") {
		t.Fatalf("renderPolicyPane did not highlight selected statement\nfull output:\n%q", joined)
	}
	if !strings.Contains(joined, "▌") {
		t.Fatalf("renderPolicyPane did not render selected statement marker\nfull output:\n%q", joined)
	}
}

func TestBuildPolicyJSONViewUsesOriginalJSONShape(t *testing.T) {
	document := analyzedDocument{
		Input: inputDocument{
			Name: "examples/demo.json",
			Raw: []byte(`{
  "Version": "2012-10-17",
  "Statement": {
    "Sid": "OnlyStatement",
    "Effect": "Allow",
    "Principal": "*",
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::demo/*"
  }
}`),
		},
		Parsed: policy.Policy{
			Version: "2012-10-17",
			Statement: policy.Statements{
				{
					SID:       "OnlyStatement",
					Effect:    "Allow",
					Principal: policy.PrincipalValue{Any: true},
					Action:    policy.StringList{"s3:GetObject"},
					Resource:  policy.StringList{"arn:aws:s3:::demo/*"},
				},
			},
		},
	}

	view := buildPolicyJSONView(document)
	got := strings.Join(view.Lines, "\n")

	if !strings.Contains(got, `"Statement": {`) {
		t.Fatalf("buildPolicyJSONView did not preserve single-object Statement shape\nfull output:\n%s", got)
	}
	if strings.Contains(got, `"Any":`) || strings.Contains(got, `"Values":`) {
		t.Fatalf("buildPolicyJSONView leaked internal principal shape\nfull output:\n%s", got)
	}
	if len(view.StatementRanges) != 1 {
		t.Fatalf("len(view.StatementRanges) = %d, want 1", len(view.StatementRanges))
	}
}

func TestRenderPanelPreservesRightBorderWithANSIContent(t *testing.T) {
	panel := renderPanel(" demo ", []string{
		"\x1b[1;92mIt\x1b[0m \x1b[1;33mwraps\x1b[0m \x1b[1;34mdemo-bucket\x1b[0m correctly.",
	}, 40, 5, 1)

	for _, line := range strings.Split(panel, "\n") {
		if visibleWidth(line) != 40 {
			t.Fatalf("visibleWidth(%q) = %d, want 40", line, visibleWidth(line))
		}
	}
}

func TestNormalizeDraftDisplayLineExpandsTabsAndDropsCarriageReturns(t *testing.T) {
	got := normalizeDraftDisplayLine("\t{\r")
	want := "    {"
	if got != want {
		t.Fatalf("normalizeDraftDisplayLine() = %q, want %q", got, want)
	}
}
