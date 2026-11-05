# Quality gates for a-witness. Run `just` to list the recipes.
#
# These run the same checks as CI (.github/workflows/check.yml); nothing here
# is looser. The Python checks need `pip install -r requirements.txt` and
# Node, and check-full also needs pip-audit installed in the same Python
# environment (`pip install pip-audit`). Set PYTHON to choose the interpreter
# (default: python3).

python := env("PYTHON", "python3")

default:
    @just --list

# Formatting, vet (lint and type checks) and the Go unit tests. A few seconds.
check-fast:
    @echo "== gofmt"
    @test -z "$(gofmt -l .)" || { echo "these files need gofmt:"; gofmt -l .; exit 1; }
    @echo "== go vet"
    go vet ./...
    @echo "== go test"
    go test ./...

# check-fast, then everything else CI runs, plus the race detector.
check-full: check-fast
    @echo "== go mod verify"
    go mod verify
    @echo "== go test -race"
    go test -race ./...
    @echo "== go test on the oldest Go that go.mod supports, as CI does"
    GOTOOLCHAIN="go$(go list -m -f '{{{{.GoVersion}}')" go test ./...
    @echo "== staticcheck, as CI runs it"
    go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...
    # The govulncheck version must match GOVULNCHECK_VERSION in .github/workflows/check.yml.
    @echo "== govulncheck on the oldest Go that go.mod supports, as CI's go job does"
    GOTOOLCHAIN="go$(go list -m -f '{{{{.GoVersion}}')" go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
    @echo "== govulncheck on the current Go, as CI's vulnerabilities job does"
    go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
    @echo "== pip-audit on requirements.txt, as CI does"
    "{{python}}" -m pip_audit -r requirements.txt
    @echo "== scripts/check.sh: examples, test vectors, Python and JavaScript cross-checks, validator cases"
    PYTHON="{{python}}" scripts/check.sh
