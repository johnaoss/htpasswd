package apr1

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"math/big"
)

const (
	// Prefix is the identifier for the Apache-specific MD5 algorithm.
	Prefix = "$apr1$"

	// Size is the size of an MD5 checksum in bytes.
	Size = 16

	// Blocksize is the blocksize of APR1 in bytes.
	Blocksize = 64

	// Rounds is the number of rounds in the big loop.
	Rounds = 1000

	// validChars is used to create a base64-like string.
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
// Must be valid UTF8 byte arrays.
// I did not design this algorithm, and the person that did should be
// placed far far away from a computer.
func HashPassword(password, salt []byte) (string, error) {
	digest := md5.New()
	digest.Write(password)
	digest.Write([]byte(Prefix))
	digest.Write(salt)

	passwordLength := len(password)

	// we now add as many characters of the MD5(pw,salt,pw)
	altDigest := md5.New()
	altDigest.Write(password)
	altDigest.Write(salt)
	altDigest.Write(password)
	alt := altDigest.Sum(nil)
	for ii := passwordLength; ii > 0; ii -= 16 {
		if ii > 16 {
			digest.Write(alt[:16])
		} else {
			digest.Write(alt[:ii])
		}
	}

	// ok this is weird
	buf := bytes.NewBuffer([]byte{})
	buf.Grow(passwordLength / 2)
	for ii := passwordLength; ii > 0; ii >>= 1 {
		if (ii & 1) == 1 {
			buf.WriteByte(0)
		} else {
			buf.WriteByte(password[0])
		}
	}

	digest.Write(buf.Bytes())
	buf.Reset()
	finalpw := digest.Sum(nil)

	// now THIS is epic
	ctx := md5.New()
	for i := 0; i < Rounds; i++ {
		if (i & 1) == 1 {
			ctx.Write(password)
		} else {
			ctx.Write(finalpw[:16])
		}

		if i%3 != 0 {
			ctx.Write(salt)
		}

		if i%7 != 0 {
			ctx.Write(password)
		}

		if (i & 1) == 1 {
			ctx.Write(finalpw[:16])
		} else {
			ctx.Write(password)
		}
		finalpw = ctx.Sum(nil)
		ctx.Reset()
	}

	// We're only going to read out 24 chars.
	buf.Grow(24)
	// 24 bits to base 64 for this
	fill := func(a byte, b byte, c byte) {
		v := (uint(a) << 16) + (uint(b) << 8) + uint(c) // take our 24 input bits

		for i := 0; i < 4; i++ { // and pump out a character for each 6 bits
			buf.WriteByte(validChars[v&0x3f])
			v >>= 6
		}
	}
	// The order of these indices is strange, be careful
	fill(finalpw[0], finalpw[6], finalpw[12])
	fill(finalpw[1], finalpw[7], finalpw[13])
	fill(finalpw[2], finalpw[8], finalpw[14])
	fill(finalpw[3], finalpw[9], finalpw[15])
	fill(finalpw[4], finalpw[10], finalpw[5])
	fill(0, 0, finalpw[11])

	resultString := string(buf.Bytes()[:22])

	// we then return the output string
	return Prefix + string(salt[:8]) + "$" + resultString, nil
}

// CompareHashes compares two hashes to see if they are identical.
func CompareHashes(new, old string) bool {
	if subtle.ConstantTimeCompare([]byte(new[:]), []byte(old[:])) == 1 {
		return true
	}
	return false
}
