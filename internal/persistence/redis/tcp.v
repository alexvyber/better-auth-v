module better_auth

import net
import strconv
import time
import x.json2

pub struct RedisTCPOptions {
pub:
	address        string = '127.0.0.1:6379'
	username       string
	password       string
	database       int
	timeout_millis int = 1000
}

pub struct RedisTCPClient {
pub:
	options RedisTCPOptions
}

// Each command gets a fresh authenticated connection. An interrupted mutation
// is never retried: its outcome is unknown. Later commands reconnect naturally.
pub fn (mut client RedisTCPClient) execute(method string, arguments []json2.Any) !json2.Any {
	if client.options.timeout_millis <= 0 || client.options.database < 0 {
		return error('invalid Redis TCP options')
	}
	mut connection := net.dial_tcp(client.options.address)!
	defer { connection.close() or {} }
	deadline := time.now().add(time.Duration(client.options.timeout_millis) * time.millisecond)
	connection.set_read_deadline(deadline)
	connection.set_write_deadline(deadline)
	connection.set_read_timeout(time.Duration(client.options.timeout_millis) * time.millisecond)
	connection.set_write_timeout(time.Duration(client.options.timeout_millis) * time.millisecond)
	mut reader := RedisRESPReader{
		connection: connection
	}
	if client.options.password != '' {
		mut auth := ['AUTH']
		if client.options.username != '' { auth << client.options.username }
		auth << client.options.password
		reader.command(auth)!
	}
	if client.options.database > 0 { reader.command(['SELECT', client.options.database.str()])! }
	mut command := if method == 'call' { []string{} } else { [
			method.to_upper(),
		] }
	for argument in arguments {
		command << argument.str()
	}
	return reader.command(command)
}

struct RedisRESPReader {
mut:
	connection &net.TcpConn
	buffer     []u8
	position   int
	received   int
}

fn (mut reader RedisRESPReader) byte() !u8 {
	if reader.position == reader.buffer.len {
		mut bytes := []u8{len: 4096}
		count := reader.connection.read(mut bytes)!
		if count == 0 { return error('Redis connection closed before its reply completed') }
		reader.received += count
		if reader.received > 8 * 1024 * 1024 {
			return error('Redis reply exceeds the native size limit')
		}
		reader.buffer = bytes[..count].clone()
		reader.position = 0
	}
	value := reader.buffer[reader.position]
	reader.position++
	return value
}

fn (mut reader RedisRESPReader) line() !string {
	mut bytes := []u8{}
	for bytes.len <= 65536 {
		value := reader.byte()!
		if value == `\r` {
			if reader.byte()! != `\n` { return error('invalid Redis reply framing') }
			return bytes.bytestr()
		}
		bytes << value
	}
	return error('Redis reply line exceeds the native size limit')
}

fn (mut reader RedisRESPReader) response(depth int) !json2.Any {
	if depth > 32 { return error('Redis reply nesting exceeds the native limit') }
	kind := reader.byte()!
	match kind {
		`+` {
			return json2.Any(reader.line()!)
		}
		`-` {
			return error(reader.line()!)
		}
		`:` {
			return json2.Any(strconv.parse_int(reader.line()!, 10, 64)!)
		}
		`$` {
			length := strconv.parse_int(reader.line()!, 10, 64)!
			if length == -1 { return json2.Any(json2.Null{}) }
			if length < 0 || length > 8 * 1024 * 1024 { return error('invalid Redis bulk length') }
			mut bytes := []u8{cap: int(length)}
			for _ in 0 .. int(length) {
				bytes << reader.byte()!
			}
			if reader.byte()! != `\r` || reader.byte()! != `\n` {
				return error('invalid Redis bulk framing')
			}
			return json2.Any(bytes.bytestr())
		}
		`*` {
			length := strconv.parse_int(reader.line()!, 10, 64)!
			if length == -1 { return json2.Any(json2.Null{}) }
			if length < 0 || length > 100000 { return error('invalid Redis array length') }
			mut values := []json2.Any{cap: int(length)}
			for _ in 0 .. int(length) {
				values << reader.response(depth + 1)!
			}
			return json2.Any(values)
		}
		else {
			return error('unsupported Redis reply type')
		}
	}
}

fn (mut reader RedisRESPReader) command(arguments []string) !json2.Any {
	if arguments.len == 0 { return error('Redis command requires a name') }
	mut encoded := '*${arguments.len}\r\n'
	for argument in arguments {
		encoded += '$${argument.len}\r\n${argument}\r\n'
	}
	reader.connection.write_string(encoded)!
	return reader.response(0)
}
