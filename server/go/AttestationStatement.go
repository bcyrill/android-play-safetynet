package main

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/dgrijalva/jwt-go"
)

type AttestationStatement struct {
	Nonce                      string
	Timestamp                  uint64
	ApkPackageName             string
	ApkDigestSha256            string
	ApkCertificateDigestSha256 string
	CtsProfileMatch            bool
	HasBasicIntegrity          bool
}

func NewWithToken(token *jwt.Token) (AttestationStatement, error) {

	var stmt AttestationStatement

	if claims, ok := token.Claims.(jwt.MapClaims); ok {

		if nonce, ok := claims["nonce"]; ok {
			stmt.Nonce = nonce.(string)
		}
		if timestamp, ok := claims["timestampMs"]; ok {
			stmt.Timestamp = uint64(timestamp.(float64))
		}
		if packageName, ok := claims["apkPackageName"]; ok {
			stmt.ApkPackageName = packageName.(string)
		}
		if apkDigest, ok := claims["apkDigestSha256"]; ok {
			bytes, err := base64.StdEncoding.DecodeString(apkDigest.(string))
			if err == nil {
				stmt.ApkDigestSha256 = string(bytes)
			}
		}
		if certificateDigest, ok := claims["apkCertificateDigestSha256"]; ok {
			for _, v := range certificateDigest.([]interface{}) {
				// TODO
				fmt.Println(v)
			}
			//stmt.ApkCertificateDigestSha256 = certificateDigest.(string)
		}
		if cts, ok := claims["ctsProfileMatch"]; ok {
			stmt.CtsProfileMatch = cts.(bool)
		}
		if basicIntegrity, ok := claims["basicIntegrity"]; ok {
			stmt.HasBasicIntegrity = basicIntegrity.(bool)
		}

		return stmt, nil
	} else {
		return stmt, errors.New("could not parse token")
	}
}
