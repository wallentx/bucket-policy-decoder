# bucket-policy-decoder

CLI that reads an S3 bucket policy from a file, stdin, pasted JSON, or an inline `--json` flag and translates it into plain English.

When output is going to a real terminal, the CLI colorizes key token types so buckets, actions, accounts, roles, services, and condition keys stand out. Set `NO_COLOR=1` to disable that.

## First-pass scope

This first pass is intentionally local-only:

- read from `--file`
- read from `--paste`
- read from `--json`
- read from `stdin`
- validate offline without AWS credentials or network access

Bucket lookups are not wired in yet.

## Usage

```bash
go run . --file examples/deny-insecure-transport.json
```

```bash
cat examples/allow-cross-account-upload.json | go run .
```

```bash
go run . --paste
```

```bash
go run . --json '{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::demo","arn:aws:s3:::demo/*"]}}'
```

If you run the tool without flags and without piped stdin, it opens a simple interactive prompt so you can choose file or pasted JSON input.

## Build

Use [`build.sh`](/data/data/com.termux/files/home/src/bucket-policy-decoder/build.sh) to build the binary locally:

```bash
./build.sh
```

The script checks for `go` first. If `go` is missing, it prints install suggestions for macOS, Linux, and Windows and exits non-zero. The built binary is written to the repository root.

On Windows, run the script from a POSIX shell such as Git Bash, MSYS2, or Cygwin.

## Output shape

The renderer produces:

- an offline validation report with errors and warnings
- a high-level count of allow and deny statements
- a plain-English reading of each statement
- a structured breakdown of principals, actions, resources, and conditions

Example:

```text
Source: examples/deny-insecure-transport.json

Validation: passed offline checks.

This policy has 1 statement.
- 1 explicit deny statement.

Plain-English reading:
1. It prevents everyone from using all S3 actions on bucket example-secure-bucket and every object in it when aws:SecureTransport is false.

Statement breakdown:
[1] DenyInsecureTransport
  Effect: DENY
  Principals: everyone
  Actions: all S3 actions
  Resources: bucket example-secure-bucket and every object in it
  Conditions:
    - aws:SecureTransport is false
```

## Offline Validation

Each run now performs local validation before rendering the policy summary.

Offline checks currently cover:

- JSON parses into a policy document
- `Version` is one of the standard IAM policy versions
- each statement has a valid `Effect`
- `Principal` and `NotPrincipal` are not both set
- `Action` and `NotAction` are not both set
- `Resource` and `NotResource` are not both set
- common shape checks for AWS principals, actions, S3 resource ARNs, and condition operators

This is intentionally best-effort validation. It catches obvious syntax and structure problems locally, but it is not a substitute for AWS service-side validation and semantic analysis.

AWS’s more complete policy validation is exposed through IAM Access Analyzer’s `ValidatePolicy` API, which requires an AWS API call and appropriate permissions:

- https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html

## Example policies

Files in [`examples/`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples):

- [`examples/deny-insecure-transport.json`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/deny-insecure-transport.json)
- [`examples/allow-cross-account-upload.json`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/allow-cross-account-upload.json)
- [`examples/require-kms-encryption.json`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/require-kms-encryption.json)
- [`examples/restrict-to-organization.json`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/restrict-to-organization.json)
- [`examples/require-storage-class.json`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/require-storage-class.json)
- [`examples/deny-everyone-except-two-principals.json`](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/deny-everyone-except-two-principals.json)

The first three are based on patterns documented in the AWS S3 example bucket policy guide, and the fourth is a custom, more complex example for stress-testing the translator.

AWS source:

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
