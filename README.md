# bucket-policy-decoder

CLI that reads an S3 bucket policy from a file, stdin, the interactive editor, or `s3://bucket` and translates it into plain English.

When output goes to a terminal, the CLI colorizes key token types so buckets, actions, accounts, roles, services, and condition keys are easy to scan. In normal interactive use, it opens a statement-focused terminal UI. Set `NO_COLOR=1` to disable color.

## Current scope

This version is local-only:

- read from file path arguments
- read from `s3://bucket` arguments
- read from `stdin`
- read from the interactive editor TUI
- validate offline
- use AWS Access Analyzer validation when usable credentials are available

For `s3://...` inputs and optional AWS-backed validation, the CLI uses the AWS SDK's default config and credential chain.

## Usage

```bash
go run . examples/deny-insecure-transport.json
```

```bash
go run . s3://my-bucket
```

```bash
go run . -s examples/*
```

```bash
cat examples/allow-cross-account-upload.json | go run .
```

If you run the tool without args and without piped stdin, it opens the interactive editor TUI with an empty JSON pane. Type or paste a policy there, then press `Ctrl+S` to decode it.

Use `-s` or `--short` to print only the plain-English reading. When the input comes from files, short mode prints the filename first and then the numbered summary for that file. If the policy has warnings or errors, they are still printed to `stderr`.

File path arguments can be individual files or glob patterns. If the shell does not expand the glob, the CLI will try to expand it itself.

`s3://bucket` and `s3://bucket/path` inputs fetch the bucket policy with the AWS SDK. If shared credentials, config, or environment credentials are available, they are used automatically. If the SDK cannot authenticate or the S3 call fails, the command returns the SDK error.

## Build

Use [build.sh](https://github.com/wallentx/bucket-policy-decoder/blob/main/build.sh) to build the binary locally:

```bash
./build.sh
```

The script checks for `go` and `gofmt` first. If `go` is missing, it prints install suggestions for macOS, Linux, and Windows and exits non-zero. It also runs:

- `go mod download` and `go mod verify`
- `gofmt` checks
- `go mod tidy` checks
- `go vet`
- `gosec`
- `go test`
- optional `staticcheck` and `golangci-lint` if those tools are installed

Use `./build.sh --fix` to apply `gofmt` and `go mod tidy` changes instead of failing. Use `./build.sh --skip-race` to skip `go test -race`.

The built binary is written to the repository root.

On Windows, run the script from a POSIX shell such as Git Bash, MSYS2, or Cygwin.

## Output shape

Normal interactive use opens a terminal UI with:

- a top pane showing the bucket policy JSON
- statement-by-statement navigation with the arrow keys
- the selected statement highlighted in the JSON
- a lower pane showing the plain-English translation for the selected statement
- warnings or errors only when the selected statement or policy has issues

If you start the tool with no args, the same UI opens in edit mode first so you can paste or type a policy directly into the top pane before decoding it with `Ctrl+S`.

If the environment does not appear to support the full-screen terminal UI cleanly, the CLI falls back to the text report automatically.

With `-s`, output is limited to the plain-English statement lines plus any warnings or errors on `stderr`.

Example:

```text
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

If the AWS SDK can load usable credentials, the CLI also asks IAM Access Analyzer for additional findings. If credentials are not available or Access Analyzer cannot be reached, the CLI silently falls back to the local checks. For `s3://...` inputs, SDK lookup errors are returned directly.

AWS exposes more complete policy validation through IAM Access Analyzer’s `ValidatePolicy` API:

- https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html
- https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html

## Example policies

Example files:

- [examples/deny-insecure-transport.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/deny-insecure-transport.json)
- [examples/allow-cross-account-upload.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/allow-cross-account-upload.json)
- [examples/require-kms-encryption.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/require-kms-encryption.json)
- [examples/restrict-to-organization.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/restrict-to-organization.json)
- [examples/require-storage-class.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/require-storage-class.json)
- [examples/deny-everyone-except-two-principals.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/deny-everyone-except-two-principals.json)

The first five are based on patterns from the AWS S3 example bucket policy guide. The last one is a custom example with explicit exceptions.

AWS source:

- https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html
