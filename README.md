# bucket-policy-decoder

Turns S3 bucket policies into plain English.

![1000026298](https://github.com/user-attachments/assets/d55f802f-dd0a-4684-b8fe-798273060985)

<img width="1344" height="880" alt="1000026303" src="https://github.com/user-attachments/assets/616a60f0-c674-4edf-b6f6-72aad57eb460" />

## Usage

```bash
bucket-policy-decoder examples/deny-insecure-transport.json
bucket-policy-decoder s3://my-bucket
bucket-policy-decoder -s examples/*
cat policy.json | bucket-policy-decoder
bucket-policy-decoder
```

Supported input:

- file paths
- glob patterns
- `s3://bucket` or `s3://bucket/path`
- `stdin`
- no args, which opens the interactive editor

## Notes

- `-s` prints only the plain-English summary
- no args opens the editor UI; paste or type JSON, then press `Ctrl+S` to decode
- normal interactive mode shows the policy JSON on top and the explanation for the selected statement below
- arrow keys move between statements
- validation is local by default
- if AWS credentials are available, the tool also uses Access Analyzer findings

## Build

```bash
./build.sh
```

The binary is written to the repo root.

## Examples

- [deny-insecure-transport.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/deny-insecure-transport.json)
- [allow-cross-account-upload.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/allow-cross-account-upload.json)
- [require-kms-encryption.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/require-kms-encryption.json)
- [restrict-to-organization.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/restrict-to-organization.json)
- [require-storage-class.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/require-storage-class.json)
- [deny-everyone-except-two-principals.json](https://github.com/wallentx/bucket-policy-decoder/blob/main/examples/deny-everyone-except-two-principals.json)
