# bucket-policy-decoder

CLI that reads an S3 bucket policy from a file, stdin, pasted JSON, or an inline `--json` flag and translates it into plain English.

When output goes to a terminal, the CLI colorizes key token types so buckets, actions, accounts, roles, services, and condition keys are easy to scan. Set `NO_COLOR=1` to disable that.

## Current scope

This version is local-only:

- read from `--file`
- read from file path arguments
- read from `--paste`
- read from `--json`
- read from `stdin`
- validate offline without AWS credentials or network access

Bucket lookups are not implemented yet.

## Usage

```bash
go run . --file examples/deny-insecure-transport.json
```

```bash
go run . examples/deny-insecure-transport.json
```

```bash
go run . --paste
```

```bash
go run . --json '{"Version":"2012-10-17","Statement":{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::demo","arn:aws:s3:::demo/*"]}}'
```

```bash
go run . -s examples/*
```

```bash
cat examples/allow-cross-account-upload.json | go run .
```

If you run the tool without flags and without piped stdin, it opens a simple interactive prompt so you can choose file or pasted JSON input.

Use `-s` or `--short` to print only the plain-English reading.

File path arguments can be individual files or glob patterns. If the shell does not expand the glob, the CLI will try to expand it itself.

## Build

Use [build.sh](/data/data/com.termux/files/home/src/bucket-policy-decoder/build.sh) to build the binary locally:

```bash
./build.sh
```

The script checks for `go` first. If `go` is missing, it prints install suggestions for macOS, Linux, and Windows and exits non-zero. The built binary is written to the repository root.

On Windows, run the script from a POSIX shell such as Git Bash, MSYS2, or Cygwin.

## Output shape

Output includes:

- an offline validation report with errors and warnings
- a high-level count of allow and deny statements
- a plain-English reading of each statement
- a structured breakdown of principals, actions, resources, and conditions

With `-s`, output is limited to the plain-English statement lines.

Example:

```text
Source: examples/deny-insecure-transport.json

Validation: passed offline checks.

This policy has 1 statement.
- 1 explicit deny statement.

Plain-English reading:
1. It prevents everyone from using all S3 actions on bucket example-secure-bucket and every object in it when the request is not using HTTPS.

Statement breakdown:
[1] DenyInsecureTransport
  Effect: DENY
  Principals: everyone
  Actions: all S3 actions
  Resources: bucket example-secure-bucket and every object in it
  Conditions:
    - the request is not using HTTPS
```

## Offline Validation

Each run validates the policy locally before rendering the summary.

The local validator checks:

- JSON parses into a policy document
- `Version` is one of the standard IAM policy versions
- each statement has a valid `Effect`
- `Principal` and `NotPrincipal` are not both set
- `Action` and `NotAction` are not both set
- `Resource` and `NotResource` are not both set
- common shape checks for AWS principals, actions, S3 resource ARNs, and condition operators

These checks catch common syntax and structure problems locally, but they do not replace AWS service-side validation and semantic analysis.

AWS exposes more complete policy validation through IAM Access Analyzer’s `ValidatePolicy` API, which requires an AWS API call and appropriate permissions:

- https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html

## Example policies

Example files:

- [examples/deny-insecure-transport.json](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/deny-insecure-transport.json)
- [examples/allow-cross-account-upload.json](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/allow-cross-account-upload.json)
- [examples/require-kms-encryption.json](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/require-kms-encryption.json)
- [examples/restrict-to-organization.json](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/restrict-to-organization.json)
- [examples/require-storage-class.json](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/require-storage-class.json)
- [examples/deny-everyone-except-two-principals.json](/data/data/com.termux/files/home/src/bucket-policy-decoder/examples/deny-everyone-except-two-principals.json)

The first five are based on patterns from the AWS S3 example bucket policy guide. The last one is a custom example with explicit exceptions.

AWS source:

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
