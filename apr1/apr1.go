package apr1

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"math/big"
	"unicode/utf8"
)

const (
	// APR1PREFIX is the identifier for the Apache-specific MD5 algorithm.
	Prefix = "$apr1$"

	// Size is the size of an MD5 checksum in bytes.
	Size = 16

	// Blocksize is the blocksize of APR1 in bytes.
	Blocksize = 64

	// ROUNDS is the number of rounds in the big loop.
	Rounds = 1000

	validChars = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

var (
	numValidChars = big.NewInt(int64(len(validChars)))
)

// generates "base64 encoded" salt for apr1-md5 hash
func generateSalt() ([]byte, error) {
	salt := make([]byte, 8)
	for i := 0; i < 8; i++ {
		res, err := rand.Int(rand.Reader, numValidChars)
		if err != nil {
			return nil, err
		}
		salt[i] = validChars[res.Uint64()]
	}
	return salt, nil
}

// HashPassword hashes the password.
func HashPassword(keyBytes []byte, salt string) (string, error) {
	// Must be valid UTF-8 files
	if !utf8.Valid(keyBytes) || !utf8.ValidString(salt) {
		return "", errors.New("key and salt must be valid UTF-8")
	}

	// Generates salt if one isn't found.
	if salt == "" {
		sb, err := generateSalt()
		if err != nil {
			return "", err
		}
		salt = string(sb)
	}

	digest := md5.New()
	saltBytes := []byte(salt)

	// we then add the key
	digest.Write(keyBytes)
	// add magic string
	digest.Write([]byte(Prefix))
	// add salt
	digest.Write(saltBytes)

	// we now add as many characters of the MD5(pw,salt,pw)
	altDigest := md5.New()
	altDigest.Write(keyBytes)
	altDigest.Write(saltBytes)
	altDigest.Write(keyBytes)
	alt := altDigest.Sum(nil)
	ii := len(keyBytes)
	for ii > 0 {
		if ii > 16 {
			digest.Write(alt[0:16])
		} else {
			digest.Write(alt[0:ii])
		}
		ii -= 16
	}
	// be secure
	for i := range alt {
		alt[i] = 0
	}

	// ok this is weird
	ii = len(keyBytes)
	for ii > 0 {
		if (ii & 1) == 1 {
			digest.Write([]byte{0})
		} else {
			digest.Write([]byte{keyBytes[0]})
		}
		ii >>= 1
	}

	// we then make the output string
	outputPrefix := Prefix + salt + "$"
	finalpw := digest.Sum(nil)

	// now THIS is epic

	for i := 0; i < Rounds; i++ {
		ctx := md5.New()
		if (i & 1) != 0 {
			ctx.Write(keyBytes)
		} else {
			ctx.Write(finalpw[0:16])
		}

		if i%3 != 0 {
			ctx.Write(saltBytes)
		}

		if i%7 != 0 {
			ctx.Write(keyBytes)
		}

		if (i & 1) != 0 {
			ctx.Write(finalpw[0:16])
		} else {
			ctx.Write(keyBytes)
		}
		finalpw = ctx.Sum(nil)
	}

	result := bytes.NewBuffer([]byte{})

	// This is our own little similar-to-base64-but-not-quite filler
	fill := func(a byte, b byte, c byte) {
		v := (uint(a) << 16) + (uint(b) << 8) + uint(c) // take our 24 input bits

		for i := 0; i < 4; i++ { // and pump out a character for each 6 bits
			result.WriteByte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[v&0x3f])
			v >>= 6
		}
	}

	// The order of these indices is strange, be careful
	fill(finalpw[0], finalpw[6], finalpw[12])
	fill(finalpw[1], finalpw[7], finalpw[13])
	fill(finalpw[2], finalpw[8], finalpw[14])
	fill(finalpw[3], finalpw[9], finalpw[15])
	fill(finalpw[4], finalpw[10], finalpw[5]) // 5?  Yes.
	fill(0, 0, finalpw[11])

	resultString := string(result.Bytes()[0:22]) // we wrote two extras since we only need 22.

	return outputPrefix + resultString, nil
}

// CompareHashes compares two hashes to see if they are identical.
func CompareHashes(new, old string) bool {
	if subtle.ConstantTimeCompare([]byte(new), []byte(old)) == 1 {
		return true
	}
	return false
}
