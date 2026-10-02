package cades

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
)

const unbounded = -1

func parseTLV(b []byte) (asn1.RawValue, []byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	return rv, rest, err
}

// parseSingle parses b as exactly one TLV.
func parseSingle(b []byte, what string) (asn1.RawValue, error) {
	rv, rest, err := parseTLV(b)
	if err != nil {
		return rv, fmt.Errorf("cades: malformed %s: %w", what, err)
	}
	if len(rest) != 0 {
		return rv, fmt.Errorf("cades: trailing data after %s", what)
	}
	return rv, nil
}

func isConstructed(rv asn1.RawValue, class, tag int) bool {
	return rv.Class == class && rv.Tag == tag && rv.IsCompound
}

func children(rv asn1.RawValue) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	for b := rv.Bytes; len(b) > 0; {
		c, rest, err := parseTLV(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}

// elements returns the children of a universal constructed value, requiring minLen to maxLen of them.
func elements(rv asn1.RawValue, tag int, kind, what string, minLen, maxLen int) ([]asn1.RawValue, error) {
	if !isConstructed(rv, asn1.ClassUniversal, tag) {
		return nil, fmt.Errorf("cades: %s is not a %s", what, kind)
	}
	c, err := children(rv)
	if err != nil {
		return nil, fmt.Errorf("cades: malformed %s: %w", what, err)
	}
	if len(c) < minLen || maxLen != unbounded && len(c) > maxLen {
		return nil, fmt.Errorf("cades: malformed %s", what)
	}
	return c, nil
}

func sequence(rv asn1.RawValue, what string, minLen, maxLen int) ([]asn1.RawValue, error) {
	return elements(rv, asn1.TagSequence, "SEQUENCE", what, minLen, maxLen)
}

func set(rv asn1.RawValue, what string) ([]asn1.RawValue, error) {
	return elements(rv, asn1.TagSet, "SET", what, 0, unbounded)
}

func parseOID(rv asn1.RawValue, what string) (asn1.ObjectIdentifier, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagOID {
		return nil, fmt.Errorf("cades: %s is not an OBJECT IDENTIFIER", what)
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(rv.FullBytes, &oid); err != nil {
		return nil, fmt.Errorf("cades: %s: %w", what, err)
	}
	return oid, nil
}

func parseInt(rv asn1.RawValue, what string) (*big.Int, error) {
	if rv.Class != asn1.ClassUniversal || rv.Tag != asn1.TagInteger {
		return nil, fmt.Errorf("cades: %s is not an INTEGER", what)
	}
	n := new(big.Int)
	if _, err := asn1.Unmarshal(rv.FullBytes, &n); err != nil {
		return nil, fmt.Errorf("cades: %s: %w", what, err)
	}
	return n, nil
}

func checkVersion1(rv asn1.RawValue, what string) error {
	v, err := parseInt(rv, what+" version")
	if err != nil {
		return err
	}
	if !v.IsInt64() || v.Int64() != 1 {
		return fmt.Errorf("cades: unsupported %s version", what)
	}
	return nil
}

func isOctetString(rv asn1.RawValue) bool {
	return rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagOctetString && !rv.IsCompound
}

// parseAlgorithm returns the algorithm OID. Absent and NULL parameters are both accepted because
// both occur for SHA-2 in the wild; RSA signature algorithms legitimately carry NULL.
func parseAlgorithm(rv asn1.RawValue, what string) (asn1.ObjectIdentifier, error) {
	c, err := sequence(rv, what, 1, 2)
	if err != nil {
		return nil, err
	}
	if len(c) == 2 && !bytes.Equal(c[1].FullBytes, asn1.NullBytes) {
		return nil, fmt.Errorf("cades: unsupported parameters in %s", what)
	}
	return parseOID(c[0], what)
}
