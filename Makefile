V ?= v

.PHONY: check test test-v test-ts integration fmt

check: test-v test-ts integration

test: test-v test-ts

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
