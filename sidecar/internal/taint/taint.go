// Package taint extracts value tokens from text, so the sidecar can tell
// whether a tool argument repeats a value the agent read in untrusted content.
//
// It extracts the value types an injected instruction typically redirects an
// agent to: email addresses, URLs and their hosts, IBANs and long digit runs
// (account and phone numbers). Each token is normalised so the same value
// written two ways matches: case-folded addresses and hosts, IBANs without
// spaces, numbers as digits only. A value of a type it does not extract, such
// as a person's name, is never tainted; that is the method's main limit.
package taint

import (
	"math/big"
	"net/url"
	"regexp"
	"strings"
)

// Token is one extracted value.
type Token struct {
	// Kind is "email", "url", "host", "iban" or "number".
	Kind  string
	Value string
}

// Key identifies a token across kinds, for set membership.
func (t Token) Key() string { return t.Kind + ":" + t.Value }

var (
	emailRe  = regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9\-]+(?:\.[a-z0-9\-]+)*\.[a-z]{2,}`)
	urlRe    = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>()\[\]{}` + "`" + `]+`)
	ibanRe   = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`)
	numberRe = regexp.MustCompile(`\+?[0-9][0-9 ().\-]{6,}[0-9]`)
	// dateRe matches dates the number pattern would otherwise read as an
	// 8-digit number, such as 2026-10-09 or 09.10.2026.
	dateRe = regexp.MustCompile(`^(?:[0-9]{4}[-/.][0-9]{1,2}[-/.][0-9]{1,2}|[0-9]{1,2}[-/.][0-9]{1,2}[-/.][0-9]{2,4})$`)
)

// Extract returns the distinct tokens in text, in order of first appearance.
func Extract(text string) []Token {
	if text == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Token
	add := func(t Token) {
		if t.Value == "" || seen[t.Key()] {
			return
		}
		seen[t.Key()] = true
		out = append(out, t)
	}

	for _, m := range emailRe.FindAllString(text, -1) {
		add(Token{Kind: "email", Value: strings.TrimRight(strings.ToLower(m), ".")})
	}
	for _, m := range urlRe.FindAllString(text, -1) {
		u, host := normaliseURL(m)
		add(Token{Kind: "url", Value: u})
		add(Token{Kind: "host", Value: host})
	}
	for _, m := range ibanRe.FindAllString(text, -1) {
		if iban := strings.ReplaceAll(m, " ", ""); validIBAN(iban) {
			add(Token{Kind: "iban", Value: iban})
		}
	}
	for _, m := range numberRe.FindAllString(text, -1) {
		if dateRe.MatchString(strings.TrimSpace(m)) {
			continue
		}
		if digits := digitsOnly(m); len(digits) >= 8 && len(digits) <= 20 {
			add(Token{Kind: "number", Value: digits})
		}
	}
	return out
}

// normaliseURL trims trailing punctuation a sentence leaves on a URL,
// lower-cases the scheme and host, drops the fragment and a default port, and
// returns the URL and its host without a leading "www.".
func normaliseURL(raw string) (string, string) {
	raw = strings.TrimRight(raw, ".,;:!?")
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(raw), ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	u.Host = host
	if port != "" {
		u.Host = host + ":" + port
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), strings.TrimPrefix(host, "www.")
}

// validIBAN checks the length and the ISO 13616 mod-97 checksum, so ordinary
// upper-case codes that happen to fit the pattern are not taken for IBANs.
func validIBAN(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4]
	var b strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteString(big.NewInt(int64(r-'A') + 10).String())
		default:
			return false
		}
	}
	n, ok := new(big.Int).SetString(b.String(), 10)
	return ok && new(big.Int).Mod(n, big.NewInt(97)).Int64() == 1
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}
