module main

import better_auth.normalization
import crypto.sha256
import encoding.hex

// Mirrors upstream's fast test hasher for ASCII fixtures. Never exported by the
// library and never selected by the standalone HTTP example.
struct TestHasher {}

fn (_ TestHasher) hash(password string) !string {
	return '$test$sha256$' + hex.encode(sha256.sum(normalization.nfkc(password).bytes()))
}

fn (h TestHasher) verify(password string, encoded string) !bool {
	expected := h.hash(password) or { return false }
	return expected == encoded
}
