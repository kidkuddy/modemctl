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
	// ESC (C0) and CSI (C1) must not reach the terminal; newlines and accents stay
	if got := printable("a\x1b[2Jb\u009bc\né"); got != "a\ufffd[2Jb\ufffdc\né" {
		t.Errorf("printable = %q", got)
	}
	if !privateMAC("D6:3E:EC:B1:FE:A7") || privateMAC("C8:89:F3:C4:49:97") || privateMAC("junk") {
		t.Error("privateMAC misclassified")
	}
	// SHA256("") known vector, uppercase like the web UI's SHA256()
	if got := sha256Hex(""); got != "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" {
		t.Errorf("sha256Hex = %s", got)
	}
	if got := md5Hex(""); got != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Errorf("md5Hex = %s", got)
	}
}
