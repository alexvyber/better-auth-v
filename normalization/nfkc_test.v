module normalization

fn from_hex_points(encoded string) string {
	return encoded.split(' ').map(hex_rune(it)).string()
}

fn test_unicode17_complete_normalization_conformance_vectors() {
	mut count := 0
	for line in $embed_file('data/conformance.txt').to_string().split_into_lines() {
		if line == '' { continue
		 }
		columns := line.split(';').map(from_hex_points(it))
		for source in columns {
			assert nfkc(source) == columns[3], 'normalization vector ${count + 1}: ${line}'
		}
		count++
	}
	assert count == 20034
}

fn test_nfkc_stability_and_empty_ascii() {
	assert nfkc('') == ''
	assert nfkc('correct horse battery staple') == 'correct horse battery staple'
	for value in ['e\u0301', '①Ｆｕｌｌ', '한글', '\u212b', 'ℌ𝔢𝔩𝔩𝔬'] {
		assert nfkc(nfkc(value)) == nfkc(value)
	}
}
