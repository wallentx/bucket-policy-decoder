#!/usr/bin/env sh

set -eu

PROJECT_NAME="bucket-policy-decoder"
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

detect_platform() {
	if [ "${OS:-}" = "Windows_NT" ]; then
		printf '%s\n' "windows"
		return
	fi

	case "$(uname -s 2>/dev/null || printf unknown)" in
		Darwin)
			printf '%s\n' "macos"
			;;
		Linux)
			printf '%s\n' "linux"
			;;
		MINGW* | MSYS* | CYGWIN*)
			printf '%s\n' "windows"
			;;
		*)
			printf '%s\n' "unknown"
			;;
	esac
}

suggest_go_install() {
	platform=$1

	printf '%s\n' "missing dependency: go"
	printf '%s\n' "install suggestions:"

	case "$platform" in
		macos)
			printf '  - Homebrew: brew install go\n'
			printf '  - Official installer: https://go.dev/dl/\n'
			;;
		linux)
			if command -v apt-get >/dev/null 2>&1; then
				printf '  - Debian/Ubuntu: sudo apt-get update && sudo apt-get install golang\n'
			fi
			if command -v dnf >/dev/null 2>&1; then
				printf '  - Fedora: sudo dnf install golang\n'
			fi
			if command -v yum >/dev/null 2>&1; then
				printf '  - RHEL/CentOS: sudo yum install golang\n'
			fi
			if command -v pacman >/dev/null 2>&1; then
				printf '  - Arch: sudo pacman -S go\n'
			fi
			if command -v zypper >/dev/null 2>&1; then
				printf '  - openSUSE: sudo zypper install go\n'
			fi
			if command -v apk >/dev/null 2>&1; then
				printf '  - Alpine: sudo apk add go\n'
			fi
			printf '  - Official tarball: https://go.dev/dl/\n'
			;;
		windows)
			printf '  - winget: winget install GoLang.Go\n'
			printf '  - Chocolatey: choco install golang\n'
			printf '  - Scoop: scoop install go\n'
			printf '  - Official installer: https://go.dev/dl/\n'
			;;
		*)
			printf '  - Install Go from: https://go.dev/dl/\n'
			;;
	esac
}

require_command() {
	name=$1
	platform=$2

	if command -v "$name" >/dev/null 2>&1; then
		return 0
	fi

	case "$name" in
		go)
			suggest_go_install "$platform"
			;;
		*)
			printf 'missing dependency: %s\n' "$name"
			;;
	esac
	return 1
}

platform=$(detect_platform)

if ! require_command go "$platform"; then
	exit 1
fi

binary_name="$PROJECT_NAME"
if [ "$platform" = "windows" ]; then
	binary_name="$binary_name.exe"
fi

printf 'building %s for %s\n' "$PROJECT_NAME" "$platform"
printf 'go version: %s\n' "$(go version)"

cd "$ROOT_DIR"
go build -o "$ROOT_DIR/$binary_name" .

printf 'built %s\n' "$ROOT_DIR/$binary_name"
