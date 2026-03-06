package policy

import (
	"strings"
	"testing"
)

func TestParseSingleStatementObject(t *testing.T) {
	input := []byte(`{
		"Version":"2012-10-17",
		"Statement":{
			"Effect":"Deny",
			"Principal":"*",
			"Action":"s3:*",
			"Resource":["arn:aws:s3:::demo","arn:aws:s3:::demo/*"]
		}
	}`)

	got, err := Parse(input)
	if err != nil {
		t.Fatalf("Parse(single statement) error: %v", err)
	}

	if len(got.Statement) != 1 {
		t.Errorf("len(got.Statement) = %d, want 1", len(got.Statement))
	}
	if !got.Statement[0].Principal.Any {
		t.Errorf("got.Statement[0].Principal.Any = %v, want true", got.Statement[0].Principal.Any)
	}
}

func TestRenderExplainsDenyEveryoneTLS(t *testing.T) {
	policyJSON := []byte(`{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Sid":"AllowCloudTrailWrite",
				"Effect":"Allow",
				"Principal":{"Service":"cloudtrail.amazonaws.com"},
				"Action":"s3:PutObject",
				"Resource":"arn:aws:s3:::logs-bucket/AWSLogs/123456789012/*",
				"Condition":{"StringEquals":{"s3:x-amz-acl":"bucket-owner-full-control"}}
			},
			{
				"Sid":"DenyInsecureTransport",
				"Effect":"Deny",
				"Principal":"*",
				"Action":"s3:*",
				"Resource":["arn:aws:s3:::logs-bucket","arn:aws:s3:::logs-bucket/*"],
				"Condition":{"Bool":{"aws:SecureTransport":"false"}}
			}
		]
	}`)

	parsed, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse(policyJSON) error: %v", err)
	}

	got := Render(parsed)

	wantParts := []string{
		"This policy has 2 statements.",
		"1 explicit deny statement.",
		"1 allow statement.",
		"Explicit denies override matching allows.",
		"It prevents everyone from using all S3 actions on bucket logs-bucket and every object in it when the request is not using HTTPS.",
		"the AWS service cloudtrail.amazonaws.com",
		`It allows the AWS service cloudtrail.amazonaws.com to upload objects to bucket logs-bucket path AWSLogs/123456789012/* only when the upload sets the ACL to "bucket-owner-full-control".`,
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Errorf("Render(parsed) missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestRenderExplainsNotPrincipalAndExceptions(t *testing.T) {
	policyJSON := []byte(`{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Sid":"DenyEveryoneExceptTwoAccounts",
				"Effect":"Deny",
				"NotPrincipal":{"AWS":["123456789012","arn:aws:iam::210987654321:role/AnalyticsReader"]},
				"Action":"s3:*",
				"Resource":["arn:aws:s3:::sensitive-data","arn:aws:s3:::sensitive-data/*"]
			}
		]
	}`)

	parsed, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse(policyJSON) error: %v", err)
	}

	got := Render(parsed)

	wantParts := []string{
		"everyone except AWS account 123456789012 and IAM role AnalyticsReader in account 210987654321",
		"all S3 actions",
		"bucket sensitive-data and every object in it",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Errorf("Render(parsed) missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestRenderHumanizesCommonS3ActionsAndConditions(t *testing.T) {
	policyJSON := []byte(`{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Deny",
				"Principal":"*",
				"Action":"s3:PutObject",
				"Resource":"arn:aws:s3:::kms-only-bucket/*",
				"Condition":{"StringNotEquals":{"s3:x-amz-server-side-encryption-aws-kms-key-id":"arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"}}
			}
		]
	}`)

	parsed, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse(policyJSON) error: %v", err)
	}

	got := Render(parsed)

	wantParts := []string{
		"It prevents everyone from being able to upload objects to bucket kms-only-bucket when the upload is not encrypted with KMS key",
		"upload objects (s3:PutObject)",
		"objects in bucket kms-only-bucket",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Errorf("Render(parsed) missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestRenderWithOptionsAddsANSIColor(t *testing.T) {
	policyJSON := []byte(`{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Principal":{"AWS":["123456789012","arn:aws:iam::210987654321:role/AnalyticsReader"]},
				"Action":["s3:GetObject","s3:ListBucket"],
				"Resource":["arn:aws:s3:::sensitive-exports","arn:aws:s3:::sensitive-exports/*"],
				"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}
			}
		]
	}`)

	parsed, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse(policyJSON) error: %v", err)
	}

	got := RenderWithOptions(parsed, RenderOptions{Color: true})

	wantParts := []string{
		"\x1b[1;36m123456789012\x1b[0m",
		"\x1b[1;35mAnalyticsReader\x1b[0m",
		"\x1b[1;33mread/download objects\x1b[0m",
		"\x1b[1;33ms3:GetObject\x1b[0m",
		"\x1b[1;34msensitive-exports\x1b[0m",
		"MFA is present",
	}
	for _, want := range wantParts {
		if !strings.Contains(got, want) {
			t.Errorf("RenderWithOptions(color) missing %q\nfull output:\n%s", want, got)
		}
	}
}

func TestValidateAcceptsReasonableBucketPolicy(t *testing.T) {
	policyJSON := []byte(`{
		"Version":"2012-10-17",
		"Statement":[
			{
				"Effect":"Allow",
				"Principal":{"AWS":["123456789012","arn:aws:iam::210987654321:role/AnalyticsReader"]},
				"Action":["s3:GetObject","s3:ListBucket"],
				"Resource":["arn:aws:s3:::sensitive-exports","arn:aws:s3:::sensitive-exports/*"],
				"Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}
			}
		]
	}`)

	parsed, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse(policyJSON) error: %v", err)
	}

	got := Validate(parsed)

	if got.HasErrors() {
		t.Errorf("Validate(parsed).HasErrors() = true, want false; findings:\n%s", got.Render(false))
	}
	if got.HasWarnings() {
		t.Errorf("Validate(parsed).HasWarnings() = true, want false; findings:\n%s", got.Render(false))
	}
}

func TestValidateReportsOfflineErrorsAndWarnings(t *testing.T) {
	policyJSON := []byte(`{
		"Version":"2015-01-01",
		"Statement":[
			{
				"Effect":"Block",
				"Principal":{"AWS":["12345","not-an-arn"]},
				"Action":["GetObject",""],
				"Resource":["bucket-name","arn:aws:s3::bad"],
				"Condition":{"Bool":{"aws:SecureTransport":["maybe"]},"MadeUpOperator":{"":["x"]}}
			}
		]
	}`)

	parsed, err := Parse(policyJSON)
	if err != nil {
		t.Fatalf("Parse(policyJSON) error: %v", err)
	}

	got := Validate(parsed)
	rendered := got.Render(false)

	wantParts := []string{
		`Version: must be "2008-10-17" or "2012-10-17"`,
		`Statement[0].Effect: must be "Allow" or "Deny"`,
		`Statement[0].Principal.AWS[0]: AWS account IDs must be 12 digits`,
		`Statement[0].Principal.AWS[1]: AWS principal is usually a 12-digit account ID or an ARN`,
		`Statement[0].Action[0]: action should usually look like "s3:GetObject" or "s3:*"`,
		`Statement[0].Action[1]: must not be empty`,
		`Statement[0].Resource[0]: resource should usually be "*" or an ARN`,
		`Statement[0].Resource[1]: S3 resource ARN format looks unusual`,
		`Statement[0].Condition.Bool.aws:SecureTransport: Bool conditions usually use "true" or "false"`,
		`Statement[0].Condition.MadeUpOperator.: condition key must not be empty`,
		`Statement[0].Condition.MadeUpOperator: operator is not in the built-in offline allowlist`,
	}
	for _, want := range wantParts {
		if !strings.Contains(rendered, want) {
			t.Errorf("Validate(parsed) missing %q\nfull findings:\n%s", want, rendered)
		}
	}
	if !got.HasErrors() {
		t.Errorf("Validate(parsed).HasErrors() = false, want true")
	}
	if !got.HasWarnings() {
		t.Errorf("Validate(parsed).HasWarnings() = false, want true")
	}
}
