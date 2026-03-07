#!/usr/bin/env sh

set -eu

PROJECT_NAME="bucket-policy-decoder"
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
FIX=0
SKIP_RACE=0
COLOR_ENABLED=0
COLOR_RESET=''
COLOR_SECTION=''
COLOR_OK=''
COLOR_WARN=''
COLOR_ERROR=''
COLOR_INFO=''

supports_color() {
	[ -t 1 ] || return 1
	[ -z "${NO_COLOR:-}" ] || return 1
	[ "${TERM:-}" != "dumb" ] || return 1
	return 0
}

setup_colors() {
	if ! supports_color; then
		return
	fi

	COLOR_ENABLED=1
	COLOR_RESET=$(printf '\033[0m')
	COLOR_SECTION=$(printf '\033[1;36m')
	COLOR_OK=$(printf '\033[1;32m')
	COLOR_WARN=$(printf '\033[1;33m')
	COLOR_ERROR=$(printf '\033[1;31m')
	COLOR_INFO=$(printf '\033[1;35m')
}

say() {
	printf '%s\n' "$*"
}

ok() {
	if [ "$COLOR_ENABLED" -eq 1 ]; then
		printf '%sOK:%s %s\n' "$COLOR_OK" "$COLOR_RESET" "$*"
		return
	fi
	printf 'OK: %s\n' "$*"
}

warn() {
	if [ "$COLOR_ENABLED" -eq 1 ]; then
		printf '%sWARN:%s %s\n' "$COLOR_WARN" "$COLOR_RESET" "$*" >&2
		return
	fi
	printf 'WARN: %s\n' "$*" >&2
}

die() {
	if [ "$COLOR_ENABLED" -eq 1 ]; then
		printf '%sERROR:%s %s\n' "$COLOR_ERROR" "$COLOR_RESET" "$*" >&2
		exit 1
	fi
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

section() {
	if [ "$COLOR_ENABLED" -eq 1 ]; then
		printf '%s==>%s %s\n' "$COLOR_SECTION" "$COLOR_RESET" "$*"
		return
	fi
	printf '==> %s\n' "$*"
}

info() {
	if [ "$COLOR_ENABLED" -eq 1 ]; then
		printf '%s%s%s\n' "$COLOR_INFO" "$*" "$COLOR_RESET"
		return
	fi
	printf '%s\n' "$*"
}

usage() {
	cat <<'EOF'
Usage: ./build.sh [--fix] [--skip-race]

  --fix        apply gofmt and go mod tidy changes instead of failing
  --skip-race  skip go test -race
EOF
}

parse_args() {
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--fix)
				FIX=1
				;;
			--skip-race)
				SKIP_RACE=1
				;;
			-h | --help)
				usage
				exit 0
				;;
			*)
				die "unknown argument: $1"
				;;
		esac
		shift
	done
}

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
		gofmt)
			printf '%s\n' "missing dependency: gofmt"
			printf '%s\n' "install suggestion: gofmt ships with Go; check that your Go installation is complete and on PATH"
			;;
		gosec)
			printf '%s\n' "missing dependency: gosec"
			printf '%s\n' "install suggestions:"
			printf '  - Go tool: go install github.com/securego/gosec/v2/cmd/gosec@latest\n'
			case "$platform" in
				macos | linux | windows)
					printf '  - Make sure "$(go env GOPATH)/bin" is on PATH after install\n'
					;;
			esac
			;;
		*)
			printf 'missing dependency: %s\n' "$name"
			;;
	esac
	return 1
}

list_go_files() {
	find . -type f -name '*.go' -not -path './vendor/*' -print
}

run_gofmt_check() {
	section "gofmt check"

	tmp_files=$(mktemp)
	tmp_issues=$(mktemp)
	trap 'rm -f "$tmp_files" "$tmp_issues"' EXIT HUP INT TERM

	list_go_files >"$tmp_files"
	if [ ! -s "$tmp_files" ]; then
		ok "no Go files found"
		rm -f "$tmp_files" "$tmp_issues"
		trap - EXIT HUP INT TERM
		return
	fi

	if [ "$FIX" -eq 1 ]; then
		while IFS= read -r file; do
			gofmt -w -s "$file"
		done <"$tmp_files"
		ok "gofmt applied"
		rm -f "$tmp_files" "$tmp_issues"
		trap - EXIT HUP INT TERM
		return
	fi

	while IFS= read -r file; do
		gofmt -l -s "$file"
	done <"$tmp_files" >"$tmp_issues"

	if [ -s "$tmp_issues" ]; then
		cat "$tmp_issues"
		die "gofmt issues found; run ./build.sh --fix"
	fi

	ok "gofmt clean"
	rm -f "$tmp_files" "$tmp_issues"
	trap - EXIT HUP INT TERM
}

run_go_mod_tidy_check() {
	section "go mod tidy check"

	tmp_dir=$(mktemp -d)
	trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

	cp go.mod "$tmp_dir/go.mod"
	if [ -f go.sum ]; then
		cp go.sum "$tmp_dir/go.sum"
	fi

	go mod tidy

	mod_changed=0
	sum_changed=0

	if ! cmp -s "$tmp_dir/go.mod" go.mod; then
		mod_changed=1
	fi

	if [ -f "$tmp_dir/go.sum" ] || [ -f go.sum ]; then
		if [ ! -f "$tmp_dir/go.sum" ] || [ ! -f go.sum ] || ! cmp -s "$tmp_dir/go.sum" go.sum; then
			sum_changed=1
		fi
	fi

	if [ "$mod_changed" -eq 1 ] || [ "$sum_changed" -eq 1 ]; then
		if [ "$FIX" -eq 1 ]; then
			ok "go mod tidy applied"
			rm -rf "$tmp_dir"
			trap - EXIT HUP INT TERM
			return
		fi

		cp "$tmp_dir/go.mod" go.mod
		if [ -f "$tmp_dir/go.sum" ]; then
			cp "$tmp_dir/go.sum" go.sum
		else
			rm -f go.sum
		fi
		die "go.mod/go.sum not tidy; run ./build.sh --fix"
	fi

	ok "go mod tidy clean"
	rm -rf "$tmp_dir"
	trap - EXIT HUP INT TERM
}

run_optional_tool() {
	tool=$1
	label=$2
	shift 2

	if ! command -v "$tool" >/dev/null 2>&1; then
		warn "$tool not found; skipping $label"
		return
	fi

	section "$label"
	"$tool" "$@"
	ok "$label passed"
}

run_race_tests() {
	if [ "$SKIP_RACE" -eq 1 ]; then
		warn "skipping race tests because --skip-race was set"
		return
	fi

	goos=$(go env GOOS)
	goarch=$(go env GOARCH)

	section "go test -race"
	case "$goos/$goarch" in
		android/* | ios/* | js/* | wasip1/*)
			warn "race detector unsupported on $goos/$goarch; skipping"
			return
			;;
	esac

	go test -race ./...
	ok "race detector clean"
}

parse_args "$@"
setup_colors
platform=$(detect_platform)

if ! require_command go "$platform"; then
	exit 1
fi
if ! require_command gofmt "$platform"; then
	exit 1
fi
if ! require_command gosec "$platform"; then
	exit 1
fi

binary_name="$PROJECT_NAME"
if [ "$platform" = "windows" ]; then
	binary_name="$binary_name.exe"
fi

info "building $PROJECT_NAME for $platform"
info "go version: $(go version)"

cd "$ROOT_DIR"

section "module verification"
go mod download
go mod verify
ok "go mod verified"

run_gofmt_check
run_go_mod_tidy_check

section "go vet"
go vet ./...
ok "go vet passed"

run_optional_tool staticcheck "staticcheck" ./...
run_optional_tool golangci-lint "golangci-lint" run

section "gosec"
gosec ./...
ok "gosec passed"

section "go test"
go test ./...
ok "tests passed"

run_race_tests

section "go build"
go build -o "$ROOT_DIR/$binary_name" .
ok "built $ROOT_DIR/$binary_name"
