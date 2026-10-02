package server

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"esign/internal/certstore"
)

const (
	maxListedDocuments = 15
	maxNameRunes       = 80
)

func confirmMessage(origin string, c certstore.Certificate, docs []documentRequest) string {
	site := confirmLocalPage
	if origin != "" {
		site = displayText(origin, maxNameRunes)
	}

	var b strings.Builder
	fmt.Fprintf(&b, confirmIntro, site)
	fmt.Fprintf(&b, confirmCert, displayText(commonName(c.Cert.Subject), maxNameRunes))
	if id := c.Cert.Subject.SerialNumber; id != "" {
		fmt.Fprintf(&b, confirmIdentity, displayText(id, maxNameRunes))
	}
	fmt.Fprintf(&b, confirmIssuer, displayText(commonName(c.Cert.Issuer), maxNameRunes))

	fmt.Fprintf(&b, confirmDocuments, len(docs))
	for i, d := range docs {
		if i == maxListedDocuments {
			fmt.Fprintf(&b, confirmMore, len(docs)-maxListedDocuments)
			break
		}
		name := d.Name
		if name == "" {
			name = d.ID
		}
		fmt.Fprintf(&b, " • %s\n", displayText(name, maxNameRunes))
	}
	b.WriteString("\n" + confirmQuestion)
	return b.String()
}

// displayText makes page-supplied text safe to show in the confirmation window: no line breaks
// or invisible direction overrides that could fake other lines of the dialog.
func displayText(s string, limit int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == limit {
			b.WriteString("…")
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r == utf8.RuneError {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
