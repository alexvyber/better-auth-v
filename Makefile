V ?= v
export V_C_ERROR_BUG_REPORT_DISABLED = 1

.PHONY: check check-package test test-v test-ts test-audit integration fmt

check: test-audit test-v test-ts integration

check-package:
	V="$(V)" node scripts/check-package.mjs

test: test-audit test-v test-ts

test-audit:
	node --test scripts/upstream-coverage.test.mjs scripts/adapter-suite-imports.test.mjs scripts/architecture.test.mjs

test-v:
	V="$(V)" node scripts/test-native.mjs

test-ts:
	V="$(V)" pnpm test
	pnpm typecheck

PACKAGE_SOURCES := $(shell find internal adapter schema domain storage normalization examples/server -type f \( -name '*.v' -o -name '*.h' -o -name 'tables.txt' \)) auth.v config.v types.v v.mod

build/auth-server: $(PACKAGE_SOURCES)
	mkdir -p build
	$(V) -d sqlite -o build/auth-server examples/server

integration: build/auth-server
	node scripts/http-smoke.mjs

fmt:
	$(V) fmt -w .
