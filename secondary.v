module better_auth

import strconv
import sync
import time

// A sentinel lets applications implement the KV interface without an extra
// availability method. Zero TTL means no expiry; positive TTL is in seconds.
pub struct NoSecondaryStorage {}

pub fn (mut _ NoSecondaryStorage) get(_ string) !Lookup[string] {
	return Lookup[string]{}
}

pub fn (mut _ NoSecondaryStorage) get_and_delete(_ string) !Lookup[string] {
	return Lookup[string]{}
}

pub fn (mut _ NoSecondaryStorage) set(_ string, _ string, _ i64) ! {
	return error('secondary storage is not configured')
}

pub fn (mut _ NoSecondaryStorage) delete(_ string) ! {}

pub fn (mut _ NoSecondaryStorage) increment(_ string, _ i64) !i64 {
	return error('secondary storage is not configured')
}

struct SecondaryEntry {
	value      string
	expires_at i64
}

@[heap]
pub struct MemorySecondaryStorage {
mut:
	entries      map[string]SecondaryEntry
	mutex        &sync.Mutex = sync.new_mutex()
	clock        fn () i64   = time.unix_now
	clock_millis fn () i64   = no_millisecond_clock
}

pub fn memory_secondary_storage(clock fn () i64) &MemorySecondaryStorage {
	return &MemorySecondaryStorage{
		clock: clock
	}
}

pub fn memory_secondary_storage_with_millis(clock fn () i64) &MemorySecondaryStorage {
	return &MemorySecondaryStorage{
		clock_millis: clock
	}
}

fn (s &MemorySecondaryStorage) now_millis() i64 {
	if s.clock_millis != no_millisecond_clock { return s.clock_millis() }
	return if s.clock == time.unix_now { time.now().unix_milli() } else { s.clock() * 1000 }
}

fn (mut s MemorySecondaryStorage) read(key string) Lookup[string] {
	entry := s.entries[key] or { return Lookup[string]{} }
	if entry.expires_at != 0 && entry.expires_at <= s.now_millis() {
		s.entries.delete(key)
		return Lookup[string]{}
	}
	return Lookup[string]{
		value: entry.value
	}
}

pub fn (mut s MemorySecondaryStorage) get(key string) !Lookup[string] {
	s.mutex.@lock()
	defer { s.mutex.unlock() }
	return s.read(key)
}

pub fn (mut s MemorySecondaryStorage) get_and_delete(key string) !Lookup[string] {
	s.mutex.@lock()
	defer { s.mutex.unlock() }
	value := s.read(key)
	s.entries.delete(key)
	return value
}

pub fn (mut s MemorySecondaryStorage) set(key string, value string, ttl i64) ! {
	if ttl < 0 { return error('TTL cannot be negative') }
	s.mutex.@lock()
	defer { s.mutex.unlock() }
	s.entries[key] = SecondaryEntry{
		value:      value
		expires_at: if ttl == 0 { 0 } else { s.now_millis() + ttl * 1000 }
	}
}

pub fn (mut s MemorySecondaryStorage) delete(key string) ! {
	s.mutex.@lock()
	defer { s.mutex.unlock() }
	s.entries.delete(key)
}

pub fn (mut s MemorySecondaryStorage) increment(key string, ttl i64) !i64 {
	if ttl < 0 { return error('TTL cannot be negative') }
	s.mutex.@lock()
	defer { s.mutex.unlock() }
	previous := s.read(key)
	mut value := i64(0)
	if encoded := previous.value { value = strconv.parse_int(encoded, 10, 64)! }
	if value == max_i64 { return error('counter overflow') }
	value++
	expires := if previous.value != none {
		s.entries[key].expires_at
	} else if ttl == 0 {
		i64(0)
	} else {
		s.now_millis() + ttl * 1000
	}
	s.entries[key] = SecondaryEntry{
		value:      value.str()
		expires_at: expires
	}
	return value
}
