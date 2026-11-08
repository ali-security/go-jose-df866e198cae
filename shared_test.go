/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/json"
)

func TestMergeHeaders(t *testing.T) {
	var dst, src rawHeader
	err := json.Unmarshal([]byte(`{"empty":"","null":null,"zero":0,"false":false,"set":"dst"}`), &dst)
	if err != nil {
		t.Fatalf("unmarshaling dst: %s", err)
	}
	err = json.Unmarshal([]byte(`{"empty":"src","null":"src","zero":"src","false":"src","set":"src","new":"src"}`), &src)
	if err != nil {
		t.Fatalf("unmarshaling src: %s", err)
	}

	dst.merge(&src)

	for k, want := range map[HeaderKey]string{
		"empty": `""`,
		"null":  `null`,
		"zero":  `0`,
		"false": `false`,
		"set":   `"dst"`,
		"new":   `"src"`,
	} {
		v, ok := dst[k]
		if !ok {
			t.Errorf("merge() dropped %q, want %s", k, want)
			continue
		}
		// A JSON null is stored as a present key with a nil value.
		got := "null"
		if v != nil {
			got = string(*v)
		}
		if got != want {
			t.Errorf("merge() set %q to %s, want %s", k, got, want)
		}
	}
}

func TestCertificatesOversizedRSA(t *testing.T) {
	defer func(old int) { MaxRSAModulusBits = old }(MaxRSAModulusBits)
	MaxRSAModulusBits = 8192

	createCert := func(subject string, isCA bool, pub *rsa.PublicKey, parent *x509.Certificate, skid []byte) *x509.Certificate {
		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: subject},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			BasicConstraintsValid: true,
			IsCA:                  isCA,
			SubjectKeyId:          skid,
		}
		if parent == nil {
			parent = template
		}
		der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, rsaTestKey)
		if err != nil {
			t.Fatalf("CreateCertificate(%q) error = %v, want nil", subject, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("ParseCertificate(%q) error = %v, want nil", subject, err)
		}
		return cert
	}

	// The oversized key needs no private key: it is never used to sign.
	n := new(big.Int).Lsh(big.NewInt(1), uint(MaxRSAModulusBits))
	oversizedKey := &rsa.PublicKey{N: n.SetBit(n, 0, 1), E: 65537}

	root := createCert("root", true, &rsaTestKey.PublicKey, nil, nil)
	leaf := createCert("leaf", false, &rsaTestKey.PublicKey, root, nil)
	oversizedLeaf := createCert("leaf", false, oversizedKey, root, nil)

	// The DoS requires the oversized key to actually be used as a verification
	// key: x509 verifies a certificate's signature against each candidate issuer
	// during chain building, and the cost of an RSA verify grows with the square
	// of the modulus. For that, the leaf's issuer must name the oversized
	// intermediate, which this builds:
	//   - the oversized intermediate carries a fixed SubjectKeyId,
	//   - the leaf is issued by a twin CA that shares that subject DN + SKID, so
	//     the leaf's issuer/AuthorityKeyId select the oversized intermediate.
	// The twin is only a way to stamp the leaf's issuer without holding the
	// (nonexistent) private key of the oversized cert; it is never put in x5c.
	// The oversized intermediate is deliberately issued by a throwaway root the
	// verifier does not trust, to show the cost (and so the fix) does not depend
	// on it chaining to the trusted root: the modexp runs before x509 checks that.
	skid := []byte{0x01, 0x02, 0x03, 0x04}
	bogusRoot := createCert("bogus-root", true, &rsaTestKey.PublicKey, nil, nil)
	oversizedKeyIntermediate := createCert("intermediate", true, oversizedKey, bogusRoot, skid)
	twinIntermediate := createCert("intermediate", true, &rsaTestKey.PublicKey, bogusRoot, skid)
	leafFromIntermediate := createCert("leaf", false, &rsaTestKey.PublicKey, twinIntermediate, nil)

	testCases := []struct {
		name    string
		chain   []*x509.Certificate
		limit   int // override for MaxRSAModulusBits, 0 for default
		wantErr string
	}{
		{
			// The actual DoS: verifying the leaf runs an RSA verify against the
			// oversized intermediate's key. The fix must reject it before chain building.
			name:    "oversized intermediate on verification path",
			chain:   []*x509.Certificate{leafFromIntermediate, oversizedKeyIntermediate},
			wantErr: "modulus too large",
		},
		{
			name:  "valid chain, no oversized key",
			chain: []*x509.Certificate{leaf},
		},
		{
			// Defense in depth, not a DoS: a leaf's own key is never used to
			// verify another certificate, but the fix rejects any oversized RSA
			// key in the chain as a matter of policy.
			name:    "oversized leaf rejected by policy",
			chain:   []*x509.Certificate{oversizedLeaf},
			wantErr: "modulus too large",
		},
		{
			// The MaxRSAModulusBits knob: raised above the key size, the same
			// chain is accepted.
			name:  "oversized leaf allowed when limit raised",
			chain: []*x509.Certificate{oversizedLeaf},
			limit: oversizedKey.N.BitLen(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			MaxRSAModulusBits = 8192

			var x5c []string
			for _, cert := range tc.chain {
				x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
			}
			signer, err := NewSigner(SigningKey{Algorithm: RS256, Key: rsaTestKey}, &SignerOptions{
				ExtraHeaders: map[HeaderKey]interface{}{HeaderKey("x5c"): x5c},
			})
			if err != nil {
				t.Fatalf("NewSigner() error = %v, want nil", err)
			}
			signed, err := signer.Sign([]byte("payload"))
			if err != nil {
				t.Fatalf("Sign() error = %v, want nil", err)
			}
			parsed, err := ParseSigned(signed.FullSerialize())
			if err != nil {
				t.Fatalf("ParseSigned() error = %v, want nil", err)
			}

			opts := x509.VerifyOptions{Roots: x509.NewCertPool()}
			opts.Roots.AddCert(root)
			if tc.limit != 0 {
				MaxRSAModulusBits = tc.limit
			}

			_, err = parsed.Signatures[0].Protected.Certificates(opts)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Certificates() error = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Certificates() error = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
