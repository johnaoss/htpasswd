package main

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"

	"golang.org/x/crypto/bcrypt"
)

func SHA1HashPassword(str string) (string, error) {
	sha := sha1.New()
	_, err := sha.Write([]byte(str))
	if err != nil {
		return "", err
	}
	hashedPw := sha.Sum(nil)
	return base64.StdEncoding.EncodeToString(hashedPw), nil
}

func MD5HashPassword(str string) (string, error) {
	md5 := md5.New()
	_, err := md5.Write([]byte(str))
	if err != nil {
		return "", err
	}
	hashedPw := md5.Sum(nil)
	return base64.StdEncoding.EncodeToString(hashedPw), nil
}

func NoHashPassword(str string) (string, error) {
	return str, nil
}

func BCRYPTHashPassword(str string, cost int) (string, error) {
	result, err := bcrypt.GenerateFromPassword([]byte(str), cost)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(result), nil
}
