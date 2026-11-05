V ?= v
export V_C_ERROR_BUG_REPORT_DISABLED = 1

.PHONY: check test test-v test-ts test-audit integration fmt

check: test-audit test-v test-ts integration

test: test-audit test-v test-ts

test-audit:
	node --test scripts/upstream-coverage.test.mjs scripts/adapter-suite-imports.test.mjs

test-v:
	$(V) test .

test-ts:
	V="$(V)" pnpm test
	pnpm typecheck

build/auth-server: *.v *.h examples/server/main.v
	mkdir -p build
	$(V) -o build/auth-server examples/server

integration: build/auth-server
	node scripts/http-smoke.mjs

fmt:
	$(V) fmt -w .
