package main

import "testing"

func TestCodecs(t *testing.T) {
	// sender name as returned by the modem for an alphanumeric sender
	if got := smsDecode("004F006F007200650064006F006F"); got != "Ooredoo" {
		t.Errorf("smsDecode = %q", got)
	}
	for _, s := range []string{"Ooredoo", "été 😀", ""} {
		if got := smsDecode(smsEncode(s)); got != s {
			t.Errorf("roundtrip %q = %q", s, got)
		}
	}
	// SHA256("") known vector, uppercase like the web UI's SHA256()
	if got := sha256Hex(""); got != "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" {
		t.Errorf("sha256Hex = %s", got)
	}
	if got := md5Hex(""); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5Hex = %s", got)
	}
}
