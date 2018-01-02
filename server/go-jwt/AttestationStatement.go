package main

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

type AttestationStatement struct {
	Nonce                      string
	Timestamp                  uint64
	ApkPackageName             string
	ApkDigestSha256            string
	ApkCertificateDigestSha256 []string
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
			stmt.ApkDigestSha256 = apkDigest.(string)
		}
		if certificateDigest, ok := claims["apkCertificateDigestSha256"]; ok {
			for _, v := range certificateDigest.([]interface{}) {
				stmt.ApkCertificateDigestSha256 = append(stmt.ApkCertificateDigestSha256, v.(string))
			}
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
