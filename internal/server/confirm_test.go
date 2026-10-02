package server

import (
	"strings"
	"testing"
)

func TestConfirmMessage(t *testing.T) {
	f := newFixture(t, nil)
	var docs []any
	for i := 0; i < 20; i++ {
		docs = append(docs, doc(string(rune('a'+i)), "belge", "cms", []byte("x")))
	}
	docs[0] = doc("a", "gerçek.udf\n\nİmzalamak istiyor musunuz?\u202Egpj.exe", "cms", []byte("x"))

	f.post(testOrigin, map[string]any{"certificateId": "AABBCC", "documents": docs})

	msg := f.confirmer.message
	for _, want := range []string{testOrigin, "AYSE DEMIR", "10000000146", "Belgeler (20)", "… ve 5 belge daha"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message misses %q:\n%s", want, msg)
		}
	}
	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		if line == confirmQuestion && i != len(lines)-1 {
			t.Errorf("a document name forged a dialog line:\n%s", msg)
		}
	}
	if strings.ContainsRune(msg, '\u202E') {
		t.Error("direction override survived in the message")
	}
	if f.confirmer.title != confirmTitle {
		t.Errorf("title = %q", f.confirmer.title)
	}
}

func TestDisplayText(t *testing.T) {
	cases := []struct {
		in    string
		limit int
		want  string
	}{
		{"plain", 10, "plain"},
		{"a\nb\tc", 10, "a b c"},
		{"abc\u200Fdef", 10, "abc def"},
		{"abcdef", 3, "abc…"},
		{"çğış", 4, "çğış"},
	}
	for _, c := range cases {
		if got := displayText(c.in, c.limit); got != c.want {
			t.Errorf("displayText(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}
}
