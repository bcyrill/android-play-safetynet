package main

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	"github.com/dgrijalva/jwt-go"
)

func parseAndVerify(signedAttestationStatement string) (*jwt.Token, error) {
	// Parse and verify the JWT token
	token, err := jwt.Parse(signedAttestationStatement, func(token *jwt.Token) (interface{}, error) {

		// Verify that the RSA signing method is used
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Verify that the header contains the certificate chain
		certs, ok := token.Header["x5c"]
		if !ok {
			return nil, fmt.Errorf("signing certificates are missing")
		}

		// prepare intermediate store as well as the leaf certificate
		intermediateStore := x509.NewCertPool()
		leafCertificate := x509.Certificate{}

		for _, v := range certs.([]interface{}) {

			// Decode Base64 to bytes
			bytes, err := base64.StdEncoding.DecodeString(v.(string))
			if err != nil {
				return nil, fmt.Errorf("failed to decode base64: " + err.Error())
			}

			// Parse Certificate
			cert, err := x509.ParseCertificate(bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: " + err.Error())
			}

			// add extracted certificates to corresponding store
			if cert.IsCA {
				intermediateStore.AddCert(cert)
			} else {
				leafCertificate = *cert
			}
		}

		// Set options for verification
		opts := x509.VerifyOptions{
			DNSName:       "attest.android.com",
			Intermediates: intermediateStore,
		}

		// Verify
		if _, err := leafCertificate.Verify(opts); err != nil {
			return nil, fmt.Errorf("failed to verify certificate: " + err.Error())
		}

		// Return pub key of certificate as key
		return leafCertificate.PublicKey, nil
	})

	if err == nil && token.Valid {
		return token, err
	} else {
		return nil, err
	}
}

func process(signedAttestationStatement string) {
	token, err := parseAndVerify(signedAttestationStatement)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Failure: Failed to parse and verify the attestation statement.")
		return
	}

	stmt, err := NewWithToken(token)

	if err == nil {
		fmt.Println("Successfully verified the attestation statement. The content is:")

		fmt.Println("Nonce: " + stmt.Nonce)
		fmt.Println("Timestamp: " + strconv.FormatUint(stmt.Timestamp, 10) + "ms")
		fmt.Println("APK package name: " + stmt.ApkPackageName)
		fmt.Println("APK digest SHA256: " + stmt.ApkDigestSha256)
		fmt.Println("APK certificate digest SHA256: " + stmt.ApkCertificateDigestSha256)
		fmt.Println("CTS profile match: " + strconv.FormatBool(stmt.CtsProfileMatch))
		fmt.Println("Has basic integrity: " + strconv.FormatBool(stmt.HasBasicIntegrity))

		fmt.Println("\nThis sample only shows how to verify the authenticity of an " +
			"attestation response. Next, you must check that the server response matches the " +
			"request by comparing the nonce, package name, timestamp and digest.")
	} else {
		fmt.Fprintln(os.Stderr, "Failure: Failed to parse the attestation contents.")
		return
	}

}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: OfflineVerify <signed attestation statement>")
		return
	}

	process(os.Args[1])
}
