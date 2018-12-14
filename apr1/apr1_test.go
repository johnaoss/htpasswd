package apr1_test

import (
	"testing"

	"github.com/johnaoss/htpasswd/apr1"
)

func TestSameOutput(t *testing.T) {
	// the htpasswd entry
	// user:$apr1$ZIOpPHmv$w.iQ7YJbtKjs/I5iTlVcl/
	result, err := apr1.HashPassword([]byte("password"), "ZIOpPHmv")
	if err != nil {
		t.Errorf(err.Error())
	}
	t.Log(result)
}
