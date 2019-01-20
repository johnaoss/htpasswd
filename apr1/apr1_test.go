package apr1_test

import (
	"crypto/subtle"
	"testing"

	"github.com/johnaoss/htpasswd/apr1"
)

// CompareHashes compares two hashes to see if they are identical.
func CompareHashes(newstr, oldstr string) bool {
	if subtle.ConstantTimeCompare([]byte(newstr[:]), []byte(oldstr[:])) == 1 {
		return true
	}
	return false
}

// TestMatchesOriginal checks to see if it matches one created by the
func TestMatchesOriginal(t *testing.T) {
	// the htpasswd entry is expected.
	expected := "$apr1$ZIOpPHmv$w.iQ7YJbtKjs/I5iTlVcl/"
	result, err := apr1.Hash("password", "ZIOpPHmv")
	if err != nil {
		t.Errorf(err.Error())
	} else if result != expected {
		t.Errorf("expected %s, given %s\n", expected, result)
	}
}

// TestHashSize validates the size of the hash.
func TestHashSize(t *testing.T) {
	// The length of the resulting hash is special.
	// The formula for counting the hash size $ + 4 + $ + 8 + $ + 22
	// Where the prefix is of length 4, salt is 8, and hash is 22.
	expected := 31 + len(apr1.Prefix)
	result, err := apr1.Hash("passwordpasswordpasswordpassword", "epicepic")
	if err != nil {
		t.Errorf(err.Error())
	} else if len(result) != expected {
		t.Errorf("expected size %d, given %d\n", expected, len(result))
	}
}

// BenchmarkAPR1Original marks the performance of the hashing function.
func BenchmarkAPR1Original(b *testing.B) {
	for i := 0; i < b.N; i++ {
		apr1.Hash("password", "saltsalt")
	}
	b.ReportAllocs()
}
