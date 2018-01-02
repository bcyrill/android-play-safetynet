package main

import (
	"fmt"
	"os"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"

	"strconv"

	"gopkg.in/square/go-jose.v2"
)

type AttestationStatement struct {
	Nonce                      string
	TimestampMs                uint64
	ApkPackageName             string
	ApkDigestSha256            string
	ApkCertificateDigestSha256 []string
	CtsProfileMatch            bool
	BasicIntegrity             bool
	Advice                     string
}

func parseAndVerify(signedAttestationStatement string) (AttestationStatement, error) {

	a, err := jose.ParseSigned(signedAttestationStatement)
	if err != nil {
		panic("could not parse the signed attestation: " + err.Error())
	}

	d, ok := a.Signatures[0].Header.ExtraHeaders["x5c"]
	if !ok {
		panic("could not obtain certificate header")
	}

	// convert []interface {} to []*Certificate
	t := d.([]interface{})
	certs := make([]*x509.Certificate, len(t))
	for i, v := range t {
		// convert base64 encoded certificate to bytes
		bytes, err := base64.StdEncoding.DecodeString(v.(string))
		if err != nil {
			panic("failed to decode base64: " + err.Error())
		}

		// convert bytes to certificate
		cert, err := x509.ParseCertificate(bytes)
		if err != nil {
			panic("failed to parse certificate: " + err.Error())
		}

		certs[i] = cert
	}

	// according to the specification, the first certificate has to be the signing certificate
	serverCert, certs := certs[0], certs[1:]

	// the remaining certificates should be intermediate CAs
	intermediateStore := x509.NewCertPool()
	for _, v := range certs {
		if !v.IsCA {
			panic("multiple leaf certificates are illegal")
		}
		intermediateStore.AddCert(v)
	}

	// set options for verification (chain and hostname)
	opts := x509.VerifyOptions{
		DNSName:       "attest.android.com",
		Intermediates: intermediateStore,
	}

	// verify the server certificate using the options above
	if _, err := serverCert.Verify(opts); err != nil {
		panic("failed to verify certificate: " + err.Error())
	}

	// verify the signature using the public key of the certificate
	b, err := a.Verify(serverCert.PublicKey)
	if err != nil {
		panic("failed signature verification")
	}

	var stmt AttestationStatement

	// unmarshal the obtained json object into an attestation statement
	err = json.Unmarshal(b, &stmt)
	if err != nil {
		panic("failed to unmarshal: " + err.Error())
	}

	return stmt, nil
}

func process(signedAttestationStatement string) {
	stmt, err := parseAndVerify(signedAttestationStatement)

	if err != nil {
		fmt.Fprintln(os.Stderr, "Failure: Failed to parse and verify the attestation statement.")
		return
	}

	fmt.Println("Successfully verified the attestation statement. The content is:")

	fmt.Println("Nonce: " + stmt.Nonce)
	fmt.Println("Timestamp: " + strconv.FormatUint(stmt.TimestampMs, 10) + "ms")
	fmt.Println("APK package name: " + stmt.ApkPackageName)
	fmt.Println("APK digest SHA256: " + stmt.ApkDigestSha256)
	fmt.Printf("APK certificate digest SHA256: %v\n", stmt.ApkCertificateDigestSha256)
	fmt.Println("CTS profile match: " + strconv.FormatBool(stmt.CtsProfileMatch))
	fmt.Println("Has basic integrity: " + strconv.FormatBool(stmt.BasicIntegrity))

	fmt.Println("\nThis sample only shows how to verify the authenticity of an " +
		"attestation response. Next, you must check that the server response matches the " +
		"request by comparing the nonce, package name, timestamp and digest.")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: OfflineVerify <signed attestation statement>")
		return
	}

	process(os.Args[1])
}
