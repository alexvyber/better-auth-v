// Unicode normalization algorithm from UAX #15. Generated data is covered by
// data/UNICODE_LICENSE; source versions and hashes are recorded in its manifest.
module normalization

import strconv

struct Tables {
	decomposition map[rune][]rune
	combining     map[rune]int
	composition   map[u64]rune
}

const tables = load_tables()

fn hex_rune(value string) rune {
	return rune(strconv.parse_uint(value, 16, 32) or { panic('invalid embedded Unicode data') })
}

fn pair_key(first rune, second rune) u64 {
	return (u64(first) << 21) | u64(second)
}

fn load_tables() Tables {
	mut decomposition := map[rune][]rune{}
	mut combining := map[rune]int{}
	mut composition := map[u64]rune{}
	for line in $embed_file('data/tables.txt').to_string().split_into_lines() {
		if line == '' { continue
		 }
		parts := line.split(';')
		match parts[0] {
			'D' { decomposition[hex_rune(parts[1])] = parts[2].split(' ').map(hex_rune(it)) }
			'C' { combining[hex_rune(parts[1])] = parts[2].int() }
			'P' { composition[pair_key(hex_rune(parts[1]), hex_rune(parts[2]))] = hex_rune(parts[3]) }
			else { panic('invalid embedded normalization record') }
		}
	}
	return Tables{
		decomposition: decomposition
		combining:     combining
		composition:   composition
	}
}

fn decompose(value rune, mut output []rune) {
	// Hangul syllables decompose algorithmically into L, V, and optional T.
	index := int(value) - 0xac00
	if index >= 0 && index < 11172 {
		output << rune(0x1100 + index / 588)
		output << rune(0x1161 + (index % 588) / 28)
		tail := index % 28
		if tail != 0 { output << rune(0x11a7 + tail) }
		return
	}
	if mapping := tables.decomposition[value] {
		for item in mapping {
			decompose(item, mut output)
		}
	} else {
		output << value
	}
}

fn compose(first rune, second rune) ?rune {
	lead := int(first) - 0x1100
	vowel := int(second) - 0x1161
	if lead >= 0 && lead < 19 && vowel >= 0 && vowel < 21 {
		return rune(0xac00 + (lead * 21 + vowel) * 28)
	}
	syllable := int(first) - 0xac00
	tail := int(second) - 0x11a7
	if syllable >= 0 && syllable < 11172 && syllable % 28 == 0 && tail > 0 && tail < 28 {
		return rune(int(first) + tail)
	}
	return tables.composition[pair_key(first, second)] or { return none }
}

pub fn nfkc(value string) string {
	mut decomposed := []rune{cap: value.len}
	for codepoint in value.runes() {
		decompose(codepoint, mut decomposed)
	}
	if decomposed.len == 0 { return '' }
	// Canonical ordering preserves equal-class order and never crosses a starter.
	for i in 1 .. decomposed.len {
		class := tables.combining[decomposed[i]]
		if class == 0 { continue
		 }
		mut j := i
		for j > 0 && tables.combining[decomposed[j - 1]] > class {
			decomposed[j], decomposed[j - 1] = decomposed[j - 1], decomposed[j]
			j--
		}
	}
	mut output := []rune{cap: decomposed.len}
	output << decomposed[0]
	mut starter := decomposed[0]
	mut starter_index := 0
	mut previous_class := tables.combining[starter]
	for codepoint in decomposed[1..] {
		class := tables.combining[codepoint]
		if composite := compose(starter, codepoint) {
			if previous_class == 0 || previous_class < class {
				output[starter_index] = composite
				starter = composite
				continue
			}
		}
		if class == 0 {
			starter_index = output.len
			starter = codepoint
		}
		output << codepoint
		previous_class = class
	}
	return output.string()
}
