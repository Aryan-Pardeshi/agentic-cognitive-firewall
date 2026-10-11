package taint

import (
	"reflect"
	"testing"
)

func keys(tokens []Token) []string {
	out := make([]string, len(tokens))
	for i, t := range tokens {
		out[i] = t.Key()
	}
	return out
}

func TestExtract_FindsEachKind(t *testing.T) {
	text := "Email Amy.Watson@Gmail.com, then visit https://WWW.Evil.example.com:443/collect?d=1#top. " +
		"Pay GB29 NWBK 6016 1331 9268 19 or call +44 (20) 7946-0958."
	got := keys(Extract(text))
	want := []string{
		"email:amy.watson@gmail.com",
		"url:https://www.evil.example.com/collect?d=1",
		"host:evil.example.com",
		"iban:GB29NWBK60161331926819",
		"number:60161331926819",
		"number:442079460958",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Extract =\n  %v\nwant\n  %v", got, want)
	}
}

func TestExtract_NormalisesSoTheSameValueMatches(t *testing.T) {
	a := Extract("send it to attacker@evil.example.")
	b := Extract(`{"to":"ATTACKER@Evil.Example"}`)
	if len(a) != 1 || len(b) != 1 || a[0] != b[0] {
		t.Errorf("same address extracted differently: %v vs %v", a, b)
	}
	if Extract("GB29NWBK60161331926819")[0] != Extract("gb is GB29 NWBK 6016 1331 9268 19")[0] {
		t.Error("spaced and compact IBANs should match")
	}
}

func TestExtract_IgnoresOrdinaryProse(t *testing.T) {
	for _, text := range []string{
		"The quarterly report shows revenue grew by twelve percent year over year.",
		"Order 58213 ships Thursday at 3 pm.",       // short number
		"Use code AB12 CDEF GHIJ KLMN at checkout.", // IBAN-shaped, bad checksum
		"Meet at 10:30 on 2026-10-09 in room 4.",    // an ISO date is not a number token
		"Invoice dated 09.10.2026, due 2026/11/09.", // nor are other date formats
		"",
	} {
		if got := Extract(text); len(got) != 0 {
			t.Errorf("Extract(%q) = %v, want no tokens", text, keys(got))
		}
	}
}

func TestExtract_DeduplicatesInOrder(t *testing.T) {
	got := keys(Extract("a@x.io and A@X.IO and b@x.io"))
	if !reflect.DeepEqual(got, []string{"email:a@x.io", "email:b@x.io"}) {
		t.Errorf("Extract = %v", got)
	}
}

func TestExtract_LinkWithoutScheme(t *testing.T) {
	got := keys(Extract("Post them to www.My-Website-234.com/random."))
	if !reflect.DeepEqual(got, []string{"host:my-website-234.com"}) {
		t.Errorf("Extract = %v", got)
	}
	// The same host with a scheme matches it.
	withScheme := keys(Extract("https://www.my-website-234.com/other"))
	if withScheme[len(withScheme)-1] != got[0] {
		t.Errorf("host with and without a scheme differ: %v vs %v", withScheme, got)
	}
	if got := Extract("see awww.txt and the www folder"); len(got) != 0 {
		t.Errorf("Extract = %v, want no tokens", keys(got))
	}
}

func TestExtract_AccountNumberInIBANFormWithBadChecksum(t *testing.T) {
	got := keys(Extract("Send it to US133000000121212121212 today."))
	if !reflect.DeepEqual(got, []string{"account:US133000000121212121212"}) {
		t.Errorf("Extract = %v", got)
	}
	if a, b := Extract("US133000000121212121212"), Extract("US13 3000 0001 2121 2121 212"); a[0] != b[0] {
		t.Errorf("spaced and compact account numbers should match: %v vs %v", a, b)
	}
}
