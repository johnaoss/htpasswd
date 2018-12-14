package apr1_test

import (
	"testing"

	"github.com/johnaoss/htpasswd/apr1"
)

func TestMatchesOriginal(t *testing.T) {
	// the htpasswd entry is expected.
	expected := "$apr1$ZIOpPHmv$w.iQ7YJbtKjs/I5iTlVcl/"
	result, err := apr1.HashPassword([]byte("password"), []byte("ZIOpPHmv"))
	if err != nil {
		t.Errorf(err.Error())
	} else if result != expected {
		t.Errorf("expected %s, given %s\n", expected, result)
	}
}

func BenchmarkAPR1Original(b *testing.B) {
	for i := 0; i < b.N; i++ {
		apr1.HashPassword([]byte("password"), []byte("password"))
	}
	b.ReportAllocs()
}
