package yumrepo

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var rpmSignatureVerificationTime = time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)

func TestVerifyEmbeddedRPMSignaturesAuthenticatesRealPGDGPackage(t *testing.T) {
	data := readPGDGRPMFixture(t)
	keyring := readPGDGPackageKeyring(t)
	reader := bytes.NewReader(data)
	if _, err := reader.Seek(7, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	proofs, err := VerifyEmbeddedRPMSignatures(context.Background(), reader, keyring, rpmSignatureVerificationTime)
	if err != nil {
		t.Fatal(err)
	}
	if offset, err := reader.Seek(0, io.SeekCurrent); err != nil || offset != 7 {
		t.Fatalf("reader offset=%d err=%v, want restored offset 7", offset, err)
	}
	if len(proofs) != 1 {
		t.Fatalf("verified signatures=%+v, want exactly one", proofs)
	}
	proof := proofs[0]
	if proof.HeaderTagID != 268 || proof.HeaderTag != "RPMSIGTAG_RSA" {
		t.Fatalf("unexpected PGDG signature tag: %+v", proof)
	}
	if proof.Coverage != RPMSignatureCoverageHeaderPayloadDigest || proof.SignedBytes <= 0 || proof.SignedBytes >= int64(len(data)) {
		t.Fatalf("unexpected PGDG signed range: %+v package_bytes=%d", proof, len(data))
	}
	if proof.SignerKeyID != proof.IssuerKeyID || len(proof.SignerFingerprint) != 40 || len(proof.SignerPrimaryFingerprint) != 40 {
		t.Fatalf("incomplete signer identity: %+v", proof)
	}
	if proof.PublicKeyAlgorithmName != "RSA" || proof.HashAlgorithmName != "SHA-256" {
		t.Fatalf("unexpected signature algorithms: %+v", proof)
	}
	if proof.PayloadDigestAlgorithm != "SHA-256" || len(proof.PayloadDigest) != 64 {
		t.Fatalf("payload digest was not authenticated: %+v", proof)
	}
	if proof.SignatureCreatedAt.IsZero() || proof.SignatureCreatedAt.After(rpmSignatureVerificationTime) {
		t.Fatalf("signature creation time was not authenticated: %+v", proof)
	}
	t.Logf("verified real PGDG RPM signer=%s fingerprint=%s primary=%s tag=%s signed_bytes=%d payload_sha256=%s",
		proof.SignerKeyID, proof.SignerFingerprint, proof.SignerPrimaryFingerprint, proof.HeaderTag, proof.SignedBytes, proof.PayloadDigest)
}

func TestVerifyEmbeddedRPMSignaturesPreservesHistoricalCentOS7PackageAt2026Observation(t *testing.T) {
	data, err := os.ReadFile("../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm")
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := os.ReadFile("testdata/RPM-GPG-KEY-CentOS-7.asc")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := InspectEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("CentOS 7 embedded signature metadata=%+v primary_key_created=%s key_matches=%d signing_matches=%d", metadata, keyring[0].PrimaryKey.CreationTime.UTC().Format(time.RFC3339), len(keyring.KeysById(keyring[0].PrimaryKey.KeyId)), len(keyring.KeysByIdUsage(keyring[0].PrimaryKey.KeyId, packet.KeyFlagSign)))
	proofs, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data), keyring, rpmSignatureVerificationTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) == 0 {
		t.Fatal("CentOS 7 RPM produced no verified signatures")
	}
	for _, proof := range proofs {
		if proof.SignerKeyID != "24c6a8a7f4a80eb5" || proof.SignatureCreatedAt.IsZero() || !proof.SignatureCreatedAt.Before(rpmSignatureVerificationTime) {
			t.Fatalf("historical CentOS 7 proof=%+v", proof)
		}
		t.Logf("verified historical CentOS 7 RPM at observation=%s using signature_time=%s signer=%s tag=%s coverage=%s",
			rpmSignatureVerificationTime.Format(time.RFC3339), proof.SignatureCreatedAt.Format(time.RFC3339), proof.SignerKeyID, proof.HeaderTag, proof.Coverage)
	}
	layout := testRPMVerificationLayout(t, data)
	headerTampered := append([]byte(nil), data...)
	headerText := headerTampered[layout.mainHeaderStart:layout.mainHeaderEnd]
	headerOffset := bytes.Index(headerText, []byte("CentOS"))
	if headerOffset < 0 {
		t.Fatal("CentOS 7 signed main header contains no stable text tamper point")
	}
	headerTampered[int(layout.mainHeaderStart)+headerOffset] = 'D'
	if _, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(headerTampered), keyring, rpmSignatureVerificationTime); !errors.Is(err, ErrRPMPackageSignature) {
		t.Fatalf("historical signed-header tamper error=%v", err)
	}
	payloadTampered := append([]byte(nil), data...)
	payloadTampered[len(payloadTampered)-1] ^= 1
	if _, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(payloadTampered), keyring, rpmSignatureVerificationTime); !errors.Is(err, ErrRPMPackageSignature) {
		t.Fatalf("historical signed-payload tamper error=%v", err)
	}
}

func TestVerifyEmbeddedRPMSignaturesPreservesCentOS4And5KeysWithoutKeyFlags(t *testing.T) {
	keyring := readHistoricalCentOSKeyring(t,
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-4",
		"../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-5",
	)
	tests := []struct {
		name        string
		filename    string
		wantKeyID   string
		missingFlag bool
		tamperProof bool
	}{
		{name: "centos4", filename: "centos-release-4-0.1.x86_64.rpm", wantKeyID: "a53d0bab443e1821", missingFlag: true, tamperProof: true},
		{name: "centos5", filename: "centos-release-5-0.0.el5.centos.2.x86_64.rpm"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../third_party/cavaliergopher-rpm/testdata", test.filename))
			if err != nil {
				t.Fatal(err)
			}
			metadata, err := InspectEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			if len(metadata) == 0 {
				t.Fatal("historical RPM contains no embedded signature")
			}
			issuer, err := strconv.ParseUint(metadata[0].IssuerKeyID, 16, 64)
			if err != nil {
				t.Fatal(err)
			}
			if len(keyring.KeysById(issuer)) == 0 {
				t.Fatalf("issuer %s is absent from explicit key bundle", metadata[0].IssuerKeyID)
			}
			if test.missingFlag && len(keyring.KeysByIdUsage(issuer, packet.KeyFlagSign)) != 0 {
				t.Fatalf("fixture no longer exercises historical missing-Key-Flags behavior for issuer %s", metadata[0].IssuerKeyID)
			}
			proofs, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data), keyring, rpmSignatureVerificationTime)
			if err != nil {
				t.Fatal(err)
			}
			if len(proofs) == 0 {
				t.Fatal("historical RPM produced no verification proof")
			}
			for _, proof := range proofs {
				if proof.SignerKeyID != metadata[0].IssuerKeyID || proof.SignatureCreatedAt.IsZero() || !proof.SignatureCreatedAt.Before(rpmSignatureVerificationTime) {
					t.Fatalf("historical proof=%+v metadata=%+v", proof, metadata)
				}
				if test.wantKeyID != "" && proof.SignerKeyID != test.wantKeyID {
					t.Fatalf("signer=%s want=%s", proof.SignerKeyID, test.wantKeyID)
				}
			}
			t.Logf("verified %s at 2026 observation: issuer=%s signature_time=%s packets=%d", test.filename, proofs[0].SignerKeyID, proofs[0].SignatureCreatedAt.Format(time.RFC3339), len(proofs))

			if !test.tamperProof {
				return
			}
			wrongKeyring := readPGDGPackageKeyring(t)
			if _, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data), wrongKeyring, rpmSignatureVerificationTime); !errors.Is(err, ErrRPMPackageSignature) {
				t.Fatalf("wrong-key error=%v", err)
			}
			layout := testRPMVerificationLayout(t, data)
			headerTampered := append([]byte(nil), data...)
			headerOffset := bytes.Index(headerTampered[layout.mainHeaderStart:layout.mainHeaderEnd], []byte("CentOS"))
			if headerOffset < 0 {
				t.Fatal("CentOS 4 signed header contains no stable tamper point")
			}
			headerTampered[int(layout.mainHeaderStart)+headerOffset] = 'D'
			if _, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(headerTampered), keyring, rpmSignatureVerificationTime); !errors.Is(err, ErrRPMPackageSignature) {
				t.Fatalf("header-tamper error=%v", err)
			}
			payloadTampered := append([]byte(nil), data...)
			payloadTampered[len(payloadTampered)-1] ^= 1
			if _, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(payloadTampered), keyring, rpmSignatureVerificationTime); !errors.Is(err, ErrRPMPackageSignature) {
				t.Fatalf("payload-tamper error=%v", err)
			}
		})
	}
}

func TestParseRPMPackageKeyringAuthenticatesRealHistoricalPackages(t *testing.T) {
	tests := []struct {
		name       string
		packageRaw string
		packageB64 string
		key        string
	}{
		{
			name:       "pgdg",
			packageB64: "../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64",
			key:        "../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc",
		},
		{
			name:       "centos4",
			packageRaw: "../../third_party/cavaliergopher-rpm/testdata/centos-release-4-0.1.x86_64.rpm",
			key:        "../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-4",
		},
		{
			name:       "centos5",
			packageRaw: "../../third_party/cavaliergopher-rpm/testdata/centos-release-5-0.0.el5.centos.2.x86_64.rpm",
			key:        "../../third_party/cavaliergopher-rpm/testdata/RPM-GPG-KEY-CentOS-5",
		},
		{
			name:       "centos7",
			packageRaw: "../../third_party/cavaliergopher-rpm/testdata/centos-release-7-2.1511.el7.centos.2.10.x86_64.rpm",
			key:        "testdata/RPM-GPG-KEY-CentOS-7.asc",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var body []byte
			var err error
			if test.packageRaw != "" {
				body, err = os.ReadFile(test.packageRaw)
			} else {
				var encoded []byte
				encoded, err = os.ReadFile(test.packageB64)
				if err == nil {
					body, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			trust, err := os.ReadFile(test.key)
			if err != nil {
				t.Fatal(err)
			}
			keyring, err := ParseRPMPackageKeyring(trust)
			if err != nil {
				t.Fatal(err)
			}
			proofs, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(body), keyring, rpmSignatureVerificationTime)
			if err != nil || len(proofs) == 0 {
				t.Fatalf("packet-preserving package trust proofs=%+v err=%v", proofs, err)
			}
		})
	}
}

func TestParseRPMPackageKeyringDoesNotTrimBinaryPacketTail(t *testing.T) {
	// This valid public key ends in 0x0b, which bytes.TrimSpace classifies as
	// whitespace. Trimming an opaque binary keyring truncates its final
	// signature packet and used to make parsing depend on random RSA bytes.
	const encoded = "xsBNBFloLwABCACo5lsIo0YHWRuxhzcY3hZEv+iaZu26/Bd8VFgNAUlxIP1EG4f4dMXiHktRtKcC1tb8phmSIOh6/yuDdxlho13k" +
		"uaYIY6GC8G7wkWvFC0XCe3jQF4LA29YpDjtrtjWH98pFs+TxOVnp7WbSB9UeLJhdcnTYQ9HCqvmAgWbxhDK1Ws1WKyhiamEoIrtu" +
		"XST0WL/HKS2ugHUrBKU8OWdiFpVp+kNRxQoXWONTWwpV5liU2OAF+5FdRHV2anMgWOg1xstofAKiwP2+QRfnl34sNaehegiCdgR6" +
		"8ClbBvqskM7gnnOaGKIWMHHeZN2M3+orOCL+owhk6XXtohHTC/U6LmdNABEBAAHNJlNPVyBTdHJlc3MgMjUgPHNvdy0yNUBleGFt" +
		"cGxlLmludmFsaWQ+wsC7BBMBCABvBYJZaC8AAgsHCRBxTLpzPy6FizUUAAAAAAAcABBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu" +
		"b3JnObEdS19Vs+Db6Jyocqp89gIVCAIWAAIZAQKbAwIeARYhBCo6JcyMqtVKvA+LbnFMunM/LoWLAAArxgf+J3gOe+NlFCO8r8Yp" +
		"amVtHGfx6D5RmZ3GcQDB1wv1nZL4xP3LtQgIAEbJ7mhqY8Y1YHN4cTV6Qq/lkKAoKihfqbCXpMlRefJujtOzSACtyQgY6DZ4lcf0" +
		"BDOW2cbr9GJdLXJffn4Aay81GAJ3GqUXXyPmr3zdhrqRH4+oiEx5Q1nL32rnQ9AH28p8HmzfsMffhAfNm3eWLyrkvdxLRhjWTKHT" +
		"Oz+FfwD9OrnoclFr4LSY2ooQl+JiA99yADcDn4TaVO2P3IveeB8Z+i4eHkOO335U7Rx8s47Q3K+f0SPzWwjtH/YjGe/rXj4SoTpR" +
		"Hv58VSpnEA9pGAgXlABdAYqjG87ATQRZaC8AAQgAx+3uzUav/HwOqJGq6RdCjUBo1WtUUxuSHMnMOomr8QYXMwGITEzHviuyjiB1" +
		"qfhZ3C4D0htRoEcWmlQr1+hzokLO1i7zmRwZdofr4I+f1HP6kMelF+GD6PGhkNcjJ2OaadviCdnS6m2ud4+jG2HHM4EJwr3mAl+Z" +
		"sRDJM2x27suQJVyy1NWc/QLX+XttVWGCTmV2UQajSO+Q251f5+9XoNLmiHbXg3nyDVMI9Ak7qJovyuyVtDe86vM9k+WjLnSPsBam" +
		"FG9xKzwFX7bvQEvNc90q7G4VvX1pPIv3bHqsc5gfiHr4oOGMuhWmWekZsFhVTIWsVSJPYYNvKPVZsbsa/QARAQABwsCsBBgBCABg" +
		"BYJZaC8ACRBxTLpzPy6FizUUAAAAAAAcABBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMub3JnBR8WGsg5NZRQBwAbvytcBQKbDBYh" +
		"BCo6JcyMqtVKvA+LbnFMunM/LoWLAABYLAf/aFqN5zZEBHDp5SUkKr5E2wThF7shDr5jftj6iYIEXg/M2tjMpMMSuPbgT5rJs0GO" +
		"6RmO69o5G1LByLOZlLW6sY3dsgnePlnxJxMLOq0WtML5kYhoLtkZ/55BoEhzjJPDT+jmfDVIGo5wxPxGr3EC+rO8WcSDW2oi5/6G" +
		"m3u9jt0ytglfvTqpzsvpi7X/ZcAY50AOA0i2Yd2w5b3WhXHhjbaYOECArFQ+qcgnANh10qI9Ofh5CQh/TYqoQI18MIwwDYT482lO" +
		"+KtmiP7lXjD8l9iCoU8NHPSt4vjG58NEk5YcxF1q6ocDdEIcvi9hO4Jd5LgCIZIhEFrHI/c4WHLkCw=="
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1333 || data[len(data)-1] != '\v' {
		t.Fatalf("regression fixture length=%d tail=%#x", len(data), data[len(data)-1])
	}
	if _, err := ParseRPMPackageKeyring(data); err != nil {
		t.Fatalf("valid binary keyring with whitespace-valued tail byte was truncated: %v", err)
	}
}

func TestParseRPMPackageKeyringAllowsOuterWhitespaceAroundArmor(t *testing.T) {
	data, err := os.ReadFile("../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if err != nil {
		t.Fatal(err)
	}
	padded := append([]byte("\n\t"), data...)
	padded = append(padded, []byte("\r\n ")...)
	if _, err := ParseRPMPackageKeyring(padded); err != nil {
		t.Fatalf("armored keyring outer whitespace was not normalized: %v", err)
	}
}

func TestParseRPMPackageKeyringRejectsTrailingPrivateArmor(t *testing.T) {
	public, err := os.ReadFile("../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if err != nil {
		t.Fatal(err)
	}
	created := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	entity, err := openpgp.NewEntity("Private tail", "", "private-tail@example.invalid", &packet.Config{
		Time: func() time.Time { return created }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	var private bytes.Buffer
	armored, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(armored, &packet.Config{Time: func() time.Time { return created }}); err != nil {
		t.Fatal(err)
	}
	if err := armored.Close(); err != nil {
		t.Fatal(err)
	}
	bundle := append(append([]byte(nil), public...), private.Bytes()...)
	if _, err := ParseRPMPackageKeyring(bundle); err == nil || !strings.Contains(err.Error(), "public-key blocks only") {
		t.Fatalf("public armor followed by private material was accepted: %v", err)
	}
	if _, err := ParsePublicKeyring(bundle); err == nil || !strings.Contains(err.Error(), "public-key blocks only") {
		t.Fatalf("metadata trust parser accepted public armor followed by private material: %v", err)
	}
}

func TestParseRPMPackageKeyringRejectsTrailingMaterialAfterBinaryPublicKeyring(t *testing.T) {
	created := time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC)
	entity, err := openpgp.NewEntity("Binary bundle", "", "binary-bundle@example.invalid", &packet.Config{
		Time: func() time.Time { return created }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	var public, private bytes.Buffer
	if err := entity.Serialize(&public); err != nil {
		t.Fatal(err)
	}
	privateArmor, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.SerializePrivate(privateArmor, &packet.Config{
		Time: func() time.Time { return created }, DefaultHash: crypto.SHA256,
	}); err != nil {
		t.Fatal(err)
	}
	if err := privateArmor.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		suffix []byte
	}{
		{name: "private-armor", suffix: private.Bytes()},
		{name: "garbage", suffix: []byte("ignored trailing garbage")},
	} {
		t.Run(test.name, func(t *testing.T) {
			bundle := append(append([]byte(nil), public.Bytes()...), test.suffix...)
			if _, err := ParseRPMPackageKeyring(bundle); err == nil {
				t.Fatal("binary package keyring accepted ignored trailing material")
			}
		})
	}
}

func TestParseRPMPackageKeyringAcceptsMultiplePublicArmorBlocks(t *testing.T) {
	first, err := os.ReadFile("../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile("testdata/RPM-GPG-KEY-CentOS-7.asc")
	if err != nil {
		t.Fatal(err)
	}
	bundle := append(append(append([]byte(nil), first...), '\n'), second...)
	if _, err := ParseRPMPackageKeyring(bundle); err != nil {
		t.Fatalf("multiple public armor blocks were rejected: %v", err)
	}
	if entities, err := ParsePublicKeyring(bundle); err != nil || len(entities) != 2 {
		t.Fatalf("metadata trust parser did not retain both public armor blocks: entities=%d err=%v", len(entities), err)
	}
}

func TestVerifyEmbeddedRPMSignaturesUsesSignatureTimeForExpiredHistoricalKey(t *testing.T) {
	keyCreated := time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)
	signatureCreated := keyCreated.Add(30 * time.Second)
	entity, err := openpgp.NewEntity("Expiring RPM Key", "", "expired-rpm@example.invalid", &packet.Config{
		Time:            func() time.Time { return keyCreated },
		RSABits:         2048,
		KeyLifetimeSecs: 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "historical-expired-key.rpm")
	writeRPMFixture(t, filename, "historical-expired-key")
	unsigned, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	const mainHeaderStart = 112
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(unsigned[mainHeaderStart:]), &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return signatureCreated },
	}); err != nil {
		t.Fatal(err)
	}
	insertFixtureSignatureTag(t, filename, 1002, signature.Bytes())
	signed, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	currentTimeReader := bytes.NewReader(signed)
	candidates, err := inspectEmbeddedRPMSignaturePackets(context.Background(), currentTimeReader)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := inspectRPMVerificationLayout(context.Background(), currentTimeReader, int64(len(signed)-currentTimeReader.Len()))
	if err != nil {
		t.Fatal(err)
	}
	_, signedStart, signedBytes := signedRPMRange(candidates[0].metadata.HeaderTagID, layout)
	if _, err := currentTimeReader.Seek(signedStart, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{entity}, io.LimitReader(currentTimeReader, signedBytes), bytes.NewReader(candidates[0].packet), &packet.Config{Time: func() time.Time { return rpmSignatureVerificationTime }}); err == nil {
		t.Fatal("control verification at 2026 unexpectedly accepted the expired historical key")
	}
	proofs, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(signed), openpgp.EntityList{entity}, rpmSignatureVerificationTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 1 || !proofs[0].SignatureCreatedAt.Equal(signatureCreated) {
		t.Fatalf("historical expired-key proof=%+v", proofs)
	}
}

func TestValidateOpenPGPSigningKeyRejectsBackdatedTrust(t *testing.T) {
	keyCreated := time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)
	entity, err := openpgp.NewEntity("Backdated RPM Key", "", "backdated-rpm@example.invalid", &packet.Config{
		Time:    func() time.Time { return keyCreated },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	keys := openpgp.EntityList{entity}.KeysById(entity.PrimaryKey.KeyId)
	if len(keys) != 1 {
		t.Fatalf("primary signer matches=%d, want 1", len(keys))
	}
	if err := validateOpenPGPSigningKeyAt(keys[0], keyCreated.Add(-time.Second)); err == nil || !strings.Contains(err.Error(), "did not exist") {
		t.Fatalf("backdated signer error=%v", err)
	}
	if err := validateOpenPGPSigningKeyAt(keys[0], keyCreated.Add(time.Second)); err != nil {
		t.Fatalf("valid signer rejected: %v", err)
	}
}

func TestVerifyEmbeddedRPMSignaturesRejectsBackdatedV4SignerKey(t *testing.T) {
	const mainHeaderStart = 112
	keyCreated := time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)
	signatureCreated := keyCreated.Add(-time.Second)
	entity, err := openpgp.NewEntity("Backdated v4 RPM Key", "", "backdated-v4-rpm@example.invalid", &packet.Config{
		Time:    func() time.Time { return keyCreated },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "backdated-v4-signer.rpm")
	writeRPMFixture(t, filename, "backdated-v4-signer")
	unsigned, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(unsigned) <= mainHeaderStart {
		t.Fatalf("unsigned fixture is only %d bytes", len(unsigned))
	}
	signingKey, ok := entity.SigningKey(keyCreated.Add(time.Second))
	if !ok || signingKey.PrivateKey == nil || signingKey.PublicKey == nil {
		t.Fatal("generated entity has no usable v4 signing key")
	}
	config := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return signatureCreated }}
	packetSignature := &packet.Signature{
		Version: signingKey.PublicKey.Version, SigType: packet.SigTypeBinary,
		PubKeyAlgo: signingKey.PublicKey.PubKeyAlgo, Hash: crypto.SHA256,
		CreationTime: signatureCreated, IssuerKeyId: &signingKey.PublicKey.KeyId,
		IssuerFingerprint: signingKey.PublicKey.Fingerprint,
	}
	hasher, err := packetSignature.PrepareSign(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(hasher, bytes.NewReader(unsigned[mainHeaderStart:])); err != nil {
		t.Fatal(err)
	}
	if err := packetSignature.Sign(hasher, signingKey.PrivateKey, config); err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := packetSignature.Serialize(&signature); err != nil {
		t.Fatal(err)
	}
	insertFixtureSignatureTag(t, filename, 1002, signature.Bytes())
	signed, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(signed), openpgp.EntityList{entity}, keyCreated.Add(time.Hour))
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "did not exist") {
		t.Fatalf("backdated v4 signer error=%v", err)
	}
}

func TestVerifyOpenPGPV4DetachedSignatureUsesHistoricalSelfCertification(t *testing.T) {
	keyCreated := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	signedAt := keyCreated.Add(time.Hour)
	renewedAt := signedAt.Add(time.Hour)
	entity, signed, detached := makeHistoricalV4SignatureFixture(t, "renewed", keyCreated, signedAt)

	identity := entity.PrimaryIdentity()
	if identity == nil || identity.UserId == nil {
		t.Fatal("generated entity has no primary identity")
	}
	primary := true
	renewal := &packet.Signature{
		Version:           entity.PrimaryKey.Version,
		SigType:           packet.SigTypePositiveCert,
		PubKeyAlgo:        entity.PrimaryKey.PubKeyAlgo,
		Hash:              crypto.SHA256,
		CreationTime:      renewedAt,
		IssuerKeyId:       &entity.PrimaryKey.KeyId,
		IssuerFingerprint: entity.PrimaryKey.Fingerprint,
		IsPrimaryId:       &primary,
		FlagsValid:        true,
		FlagCertify:       true,
		FlagSign:          true,
	}
	config := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return renewedAt }}
	if err := renewal.SignUserId(identity.UserId.Id, entity.PrimaryKey, entity.PrivateKey, config); err != nil {
		t.Fatal(err)
	}
	identity.Signatures = append(identity.Signatures, renewal)
	keyring := publicV4Keyring(t, entity)
	latest, _ := keyring[0].PrimarySelfSignature()
	if latest == nil || !latest.CreationTime.Equal(renewedAt) {
		t.Fatalf("fixture latest self-certification=%v, want %s", latest, renewedAt)
	}

	key, err := verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached, keyring, signedAt)
	if err != nil {
		t.Fatalf("historical signature rejected after certificate renewal: %v", err)
	}
	if key.PublicKey == nil || key.PublicKey.KeyId != entity.PrimaryKey.KeyId {
		t.Fatalf("historical signer=%+v, want primary key %016x", key, entity.PrimaryKey.KeyId)
	}
}

func TestVerifyOpenPGPV4DetachedSignatureAppliesRevocationTimeSemantics(t *testing.T) {
	tests := []struct {
		name       string
		reason     packet.ReasonForRevocation
		wantVerify bool
	}{
		{name: "retired", reason: packet.KeyRetired, wantVerify: true},
		{name: "compromised", reason: packet.KeyCompromised, wantVerify: false},
		{name: "unspecified", reason: packet.NoReason, wantVerify: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyCreated := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
			signedAt := keyCreated.Add(time.Hour)
			revokedAt := signedAt.Add(time.Hour)
			entity, signed, detached := makeHistoricalV4SignatureFixture(t, test.name, keyCreated, signedAt)
			if err := entity.RevokeKey(test.reason, test.name, &packet.Config{
				DefaultHash: crypto.SHA256,
				Time:        func() time.Time { return revokedAt },
			}); err != nil {
				t.Fatal(err)
			}
			keyring := publicV4Keyring(t, entity)
			_, err := verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached, keyring, signedAt)
			if test.wantVerify && err != nil {
				t.Fatalf("signature predating normal retirement rejected: %v", err)
			}
			if !test.wantVerify && err == nil {
				t.Fatalf("signature accepted after retroactive %s revocation", test.name)
			}
			if test.reason == packet.KeyRetired {
				keys := keyring.KeysById(entity.PrimaryKey.KeyId)
				if len(keys) != 1 {
					t.Fatalf("retired signer matches=%d, want 1", len(keys))
				}
				if err := validateOpenPGPSigningKeyAt(keys[0], revokedAt.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "revoked") {
					t.Fatalf("post-retirement signer validation error=%v", err)
				}
			}
		})
	}
}

func TestParseRPMPackageKeyringPreservesHistoricalSigningSubkeyBindings(t *testing.T) {
	keyCreated := time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)
	subkeyCreated := keyCreated.Add(time.Minute)
	signedAt := subkeyCreated.Add(time.Minute)
	renewedAt := signedAt.Add(time.Minute)
	entity, err := openpgp.NewEntity("Historical subkey", "", "subkey@example.invalid", &packet.Config{
		Time:    func() time.Time { return keyCreated },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddSigningSubkey(&packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return subkeyCreated },
		RSABits:     2048,
	}); err != nil {
		t.Fatal(err)
	}
	subkey := &entity.Subkeys[len(entity.Subkeys)-1]
	if subkey.PublicKey == nil || subkey.PrivateKey == nil || subkey.Sig == nil || !subkey.Sig.FlagSign {
		t.Fatal("generated entity has no signing subkey")
	}
	signed := []byte("historical signing-subkey package signature")
	var detached bytes.Buffer
	if err := openpgp.DetachSign(&detached, entity, bytes.NewReader(signed), &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return signedAt },
	}); err != nil {
		t.Fatal(err)
	}
	packetReader := packet.NewReader(bytes.NewReader(detached.Bytes()))
	value, err := packetReader.Next()
	if err != nil {
		t.Fatal(err)
	}
	detachedPacket, ok := value.(*packet.Signature)
	if !ok || detachedPacket.IssuerKeyId == nil || *detachedPacket.IssuerKeyId != subkey.PublicKey.KeyId {
		t.Fatalf("detached signature issuer=%+v, want signing subkey %016x", detachedPacket, subkey.PublicKey.KeyId)
	}

	renewal := makeSigningSubkeyBinding(t, entity, subkey, renewedAt, true)
	encoded := serializePublicEntityWithAdditionalSubkeyBinding(t, entity, subkey.PublicKey.KeyId, renewal)
	legacy, err := openpgp.ReadKeyRing(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached.Bytes(), legacy, signedAt); err == nil || !strings.Contains(err.Error(), "binding did not exist") {
		t.Fatalf("control legacy keyring did not reproduce lost historical binding: %v", err)
	}
	historical, err := ParseRPMPackageKeyring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	fingerprints, err := RPMPackageKeyringPrimaryFingerprints(encoded)
	if err != nil {
		t.Fatalf("enumerate historical package trust identities: %v", err)
	}
	wantedFingerprint := hex.EncodeToString(entity.PrimaryKey.Fingerprint)
	if len(fingerprints) != 1 || fingerprints[0] != wantedFingerprint {
		t.Fatalf("historical package trust fingerprints=%v, want %s", fingerprints, wantedFingerprint)
	}
	key, err := verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached.Bytes(), historical, signedAt)
	if err != nil {
		t.Fatalf("historical signing-subkey signature rejected after binding renewal: %v", err)
	}
	if key.PublicKey == nil || key.PublicKey.KeyId != subkey.PublicKey.KeyId {
		t.Fatalf("historical signer=%+v, want subkey %016x", key, subkey.PublicKey.KeyId)
	}
}

func TestHistoricalSubkeyBindingCannotOverrideLaterUsageOrLifetimePolicy(t *testing.T) {
	tests := []struct {
		name            string
		allowSign       bool
		lifetime        *uint32
		bindingLifetime *uint32
		wantError       string
	}{
		{name: "signing-permission-removed", allowSign: false, wantError: "flags do not permit signing"},
		{name: "key-lifetime-shortened", allowSign: true, lifetime: uint32Pointer(120), wantError: "subkey was not valid"},
		{name: "binding-expired", allowSign: true, bindingLifetime: uint32Pointer(60), wantError: "subkey was not valid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyCreated := time.Date(2025, 3, 2, 0, 0, 0, 0, time.UTC)
			subkeyCreated := keyCreated.Add(time.Minute)
			policyAt := subkeyCreated.Add(time.Minute)
			signedAt := subkeyCreated.Add(3 * time.Minute)
			entity, err := openpgp.NewEntity("Restrictive subkey policy", "", "restrict-subkey@example.invalid", &packet.Config{
				Time: func() time.Time { return keyCreated }, RSABits: 2048,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := entity.AddSigningSubkey(&packet.Config{
				DefaultHash: crypto.SHA256, Time: func() time.Time { return subkeyCreated }, RSABits: 2048,
			}); err != nil {
				t.Fatal(err)
			}
			subkey := &entity.Subkeys[len(entity.Subkeys)-1]
			signed := []byte("signature made after restrictive subkey policy")
			var detached bytes.Buffer
			if err := openpgp.DetachSign(&detached, entity, bytes.NewReader(signed), &packet.Config{
				DefaultHash: crypto.SHA256, Time: func() time.Time { return signedAt },
			}); err != nil {
				t.Fatal(err)
			}
			policy := makeSubkeyBindingWithLifetimes(t, entity, subkey, policyAt, test.allowSign, test.allowSign, test.lifetime, test.bindingLifetime, nil)
			encoded := serializePublicEntityWithAdditionalSubkeyBinding(t, entity, subkey.PublicKey.KeyId, policy)
			keyring, err := ParseRPMPackageKeyring(encoded)
			if err != nil {
				t.Fatal(err)
			}
			temporal, ok := keyring.(openPGPTemporalKeyRing)
			if !ok {
				t.Fatal("package keyring does not implement time-aware lookup")
			}
			selected := temporal.KeysByIdAt(subkey.PublicKey.KeyId, signedAt)
			if len(selected) != 1 || selected[0].SelfSignature == nil || !selected[0].SelfSignature.CreationTime.Equal(policyAt) {
				t.Fatalf("time-aware selected bindings=%+v, want policy at %s", selected, policyAt)
			}
			_, err = verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached.Bytes(), keyring, signedAt)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("older permissive subkey binding overrode %s: %v", test.name, err)
			}
		})
	}
}

func TestHistoricalPrimarySelfCertificationCannotOverrideLaterUsageOrLifetimePolicy(t *testing.T) {
	tests := []struct {
		name        string
		allowSign   bool
		lifetime    *uint32
		sigLifetime *uint32
		wantError   string
	}{
		{name: "signing-permission-removed", allowSign: false, wantError: "flags do not permit signing"},
		{name: "key-lifetime-shortened", allowSign: true, lifetime: uint32Pointer(120), wantError: "primary key was not valid"},
		{name: "self-certification-expired", allowSign: true, sigLifetime: uint32Pointer(60), wantError: "primary key was not valid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyCreated := time.Date(2025, 3, 3, 0, 0, 0, 0, time.UTC)
			policyAt := keyCreated.Add(time.Minute)
			signedAt := keyCreated.Add(3 * time.Minute)
			entity, signed, detached := makeHistoricalV4SignatureFixture(t, test.name, keyCreated, signedAt)
			identity := entity.PrimaryIdentity()
			if identity == nil || identity.UserId == nil {
				t.Fatal("generated entity has no primary identity")
			}
			primary := true
			policy := &packet.Signature{
				Version: entity.PrimaryKey.Version, SigType: packet.SigTypePositiveCert,
				PubKeyAlgo: entity.PrimaryKey.PubKeyAlgo, Hash: crypto.SHA256,
				CreationTime: policyAt, IssuerKeyId: &entity.PrimaryKey.KeyId,
				IssuerFingerprint: entity.PrimaryKey.Fingerprint,
				IsPrimaryId:       &primary, FlagsValid: true, FlagCertify: true,
				FlagSign: test.allowSign, KeyLifetimeSecs: test.lifetime, SigLifetimeSecs: test.sigLifetime,
			}
			if err := policy.SignUserId(identity.UserId.Id, entity.PrimaryKey, entity.PrivateKey, &packet.Config{
				DefaultHash: crypto.SHA256, Time: func() time.Time { return policyAt },
			}); err != nil {
				t.Fatal(err)
			}
			identity.Signatures = append(identity.Signatures, policy)
			var encoded bytes.Buffer
			if err := entity.Serialize(&encoded); err != nil {
				t.Fatal(err)
			}
			keyring, err := ParseRPMPackageKeyring(encoded.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached, keyring, signedAt)
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("older permissive primary self-certification overrode %s: %v", test.name, err)
			}
		})
	}
}

func TestPrimarySelfSignatureAtRejectsEqualTimePrimaryIdentityPolicies(t *testing.T) {
	created := time.Date(2025, 3, 4, 0, 0, 0, 0, time.UTC)
	policyAt := created.Add(time.Minute)
	entity, err := openpgp.NewEntity("First identity", "", "first@example.invalid", &packet.Config{
		Time: func() time.Time { return created }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	primary := true
	makePolicy := func(userID *packet.UserId, allowSign bool) *packet.Signature {
		t.Helper()
		signature := &packet.Signature{
			Version: entity.PrimaryKey.Version, SigType: packet.SigTypePositiveCert,
			PubKeyAlgo: entity.PrimaryKey.PubKeyAlgo, Hash: crypto.SHA256,
			CreationTime: policyAt, IssuerKeyId: &entity.PrimaryKey.KeyId,
			IssuerFingerprint: entity.PrimaryKey.Fingerprint,
			IsPrimaryId:       &primary, FlagsValid: true, FlagCertify: true, FlagSign: allowSign,
		}
		if err := signature.SignUserId(userID.Id, entity.PrimaryKey, entity.PrivateKey, &packet.Config{
			DefaultHash: crypto.SHA256, Time: func() time.Time { return policyAt },
		}); err != nil {
			t.Fatal(err)
		}
		return signature
	}
	first := entity.PrimaryIdentity()
	if first == nil || first.UserId == nil {
		t.Fatal("generated primary identity is missing")
	}
	firstPolicy := makePolicy(first.UserId, true)
	first.Signatures = append(first.Signatures, firstPolicy)
	secondUserID := packet.NewUserId("Second identity", "", "second@example.invalid")
	if secondUserID == nil {
		t.Fatal("create second user ID")
	}
	secondPolicy := makePolicy(secondUserID, false)
	entity.Identities[secondUserID.Id] = &openpgp.Identity{
		Name: secondUserID.Id, UserId: secondUserID, SelfSignature: secondPolicy,
		Signatures: []*packet.Signature{secondPolicy},
	}
	if _, _, err := primarySelfSignatureAt(entity, policyAt.Add(time.Second)); err == nil || !strings.Contains(err.Error(), "ambiguous primary identities") {
		t.Fatalf("equal-time conflicting primary identity policies were accepted: %v", err)
	}
}

func TestValidateOpenPGPSigningKeyRejectsMissingSubkeyCrossCertification(t *testing.T) {
	createdAt := time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC)
	entity, err := openpgp.NewEntity("Missing cross cert", "", "missing-cross@example.invalid", &packet.Config{
		Time:    func() time.Time { return createdAt },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddSigningSubkey(&packet.Config{Time: func() time.Time { return createdAt.Add(time.Minute) }, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	subkey := &entity.Subkeys[len(entity.Subkeys)-1]
	withoutCross := makeSigningSubkeyBinding(t, entity, subkey, createdAt.Add(2*time.Minute), false)
	key := openpgp.Key{
		Entity: entity, PublicKey: subkey.PublicKey, PrivateKey: subkey.PrivateKey,
		SelfSignature: withoutCross, Revocations: subkey.Revocations,
	}
	if err := validateOpenPGPSigningKeyAt(key, createdAt.Add(3*time.Minute)); err == nil || !strings.Contains(err.Error(), "cross-signature") {
		t.Fatalf("missing signing-subkey cross-certification error=%v", err)
	}
}

func TestExpiredSigningSubkeyCrossCertificationIsRejected(t *testing.T) {
	keyCreated := time.Date(2025, 4, 2, 0, 0, 0, 0, time.UTC)
	bindingAt := keyCreated.Add(time.Minute)
	signedAt := bindingAt.Add(2 * time.Minute)
	entity, err := openpgp.NewEntity("Expired cross cert", "", "expired-cross@example.invalid", &packet.Config{
		Time: func() time.Time { return keyCreated }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddSigningSubkey(&packet.Config{Time: func() time.Time { return bindingAt }, RSABits: 2048}); err != nil {
		t.Fatal(err)
	}
	subkey := &entity.Subkeys[len(entity.Subkeys)-1]
	subkey.Sig = makeSubkeyBindingWithCrossLifetime(t, entity, subkey, bindingAt, true, true, nil, uint32Pointer(60))
	signed := []byte("signature after embedded cross-certification expiry")
	var detached bytes.Buffer
	if err := openpgp.DetachSign(&detached, entity, bytes.NewReader(signed), &packet.Config{
		DefaultHash: crypto.SHA256, Time: func() time.Time { return signedAt },
	}); err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := entity.Serialize(&encoded); err != nil {
		t.Fatal(err)
	}
	legacy, err := openpgp.ReadKeyRing(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	keys := legacy.KeysById(subkey.PublicKey.KeyId)
	if len(keys) != 1 {
		t.Fatalf("signing-subkey matches=%d, want 1", len(keys))
	}
	if err := validateOpenPGPSigningKeyAt(keys[0], signedAt); err == nil || !strings.Contains(err.Error(), "cross-certification") {
		t.Fatalf("expired cross-certification validation error=%v", err)
	}
	keyring, err := ParseRPMPackageKeyring(encoded.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached.Bytes(), keyring, signedAt); err == nil {
		t.Fatal("signature accepted after its only signing-subkey cross-certification expired")
	}
}

func TestExpiredNewestCrossCertificationCannotResurrectOlderBinding(t *testing.T) {
	keyCreated := time.Date(2025, 4, 3, 0, 0, 0, 0, time.UTC)
	subkeyCreated := keyCreated.Add(time.Minute)
	policyAt := subkeyCreated.Add(time.Minute)
	signedAt := policyAt.Add(2 * time.Minute)
	entity, err := openpgp.NewEntity("Cross fallback", "", "cross-fallback@example.invalid", &packet.Config{
		Time: func() time.Time { return keyCreated }, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := entity.AddSigningSubkey(&packet.Config{
		DefaultHash: crypto.SHA256, Time: func() time.Time { return subkeyCreated }, RSABits: 2048,
	}); err != nil {
		t.Fatal(err)
	}
	subkey := &entity.Subkeys[len(entity.Subkeys)-1]
	signed := []byte("signature after newest cross-certification expired")
	var detached bytes.Buffer
	if err := openpgp.DetachSign(&detached, entity, bytes.NewReader(signed), &packet.Config{
		DefaultHash: crypto.SHA256, Time: func() time.Time { return signedAt },
	}); err != nil {
		t.Fatal(err)
	}
	newest := makeSubkeyBindingWithCrossLifetime(t, entity, subkey, policyAt, true, true, nil, uint32Pointer(60))
	encoded := serializePublicEntityWithAdditionalSubkeyBinding(t, entity, subkey.PublicKey.KeyId, newest)
	keyring, err := ParseRPMPackageKeyring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOpenPGPV4DetachedSignature(bytes.NewReader(signed), detached.Bytes(), keyring, signedAt); err == nil || !strings.Contains(err.Error(), "cross-certification") {
		t.Fatalf("expired newest cross-certification resurrected older binding: %v", err)
	}
}

func makeSigningSubkeyBinding(t *testing.T, entity *openpgp.Entity, subkey *openpgp.Subkey, createdAt time.Time, crossCertified bool) *packet.Signature {
	return makeSubkeyBinding(t, entity, subkey, createdAt, true, crossCertified, nil)
}

func makeSubkeyBinding(t *testing.T, entity *openpgp.Entity, subkey *openpgp.Subkey, createdAt time.Time, allowSign, crossCertified bool, lifetime *uint32) *packet.Signature {
	return makeSubkeyBindingWithLifetimes(t, entity, subkey, createdAt, allowSign, crossCertified, lifetime, nil, nil)
}

func makeSubkeyBindingWithCrossLifetime(t *testing.T, entity *openpgp.Entity, subkey *openpgp.Subkey, createdAt time.Time, allowSign, crossCertified bool, lifetime, crossLifetime *uint32) *packet.Signature {
	return makeSubkeyBindingWithLifetimes(t, entity, subkey, createdAt, allowSign, crossCertified, lifetime, nil, crossLifetime)
}

func makeSubkeyBindingWithLifetimes(t *testing.T, entity *openpgp.Entity, subkey *openpgp.Subkey, createdAt time.Time, allowSign, crossCertified bool, lifetime, bindingLifetime, crossLifetime *uint32) *packet.Signature {
	t.Helper()
	config := &packet.Config{DefaultHash: crypto.SHA256, Time: func() time.Time { return createdAt }}
	binding := &packet.Signature{
		Version: entity.PrimaryKey.Version, SigType: packet.SigTypeSubkeyBinding,
		PubKeyAlgo: entity.PrimaryKey.PubKeyAlgo, Hash: crypto.SHA256,
		CreationTime: createdAt, IssuerKeyId: &entity.PrimaryKey.KeyId,
		IssuerFingerprint: entity.PrimaryKey.Fingerprint,
		FlagsValid:        true, FlagSign: allowSign, KeyLifetimeSecs: lifetime,
		SigLifetimeSecs: bindingLifetime,
	}
	if crossCertified {
		binding.EmbeddedSignature = &packet.Signature{
			Version: subkey.PublicKey.Version, SigType: packet.SigTypePrimaryKeyBinding,
			PubKeyAlgo: subkey.PublicKey.PubKeyAlgo, Hash: crypto.SHA256,
			CreationTime: createdAt, IssuerKeyId: &subkey.PublicKey.KeyId,
			IssuerFingerprint: subkey.PublicKey.Fingerprint, SigLifetimeSecs: crossLifetime,
		}
		if err := binding.EmbeddedSignature.CrossSignKey(subkey.PublicKey, entity.PrimaryKey, subkey.PrivateKey, config); err != nil {
			t.Fatal(err)
		}
	}
	if err := binding.SignKey(subkey.PublicKey, entity.PrivateKey, config); err != nil {
		t.Fatal(err)
	}
	return binding
}

func uint32Pointer(value uint32) *uint32 { return &value }

func serializePublicEntityWithAdditionalSubkeyBinding(t *testing.T, entity *openpgp.Entity, subkeyID uint64, additional *packet.Signature) []byte {
	t.Helper()
	var encoded bytes.Buffer
	if err := entity.PrimaryKey.Serialize(&encoded); err != nil {
		t.Fatal(err)
	}
	for _, signature := range entity.Revocations {
		if err := signature.Serialize(&encoded); err != nil {
			t.Fatal(err)
		}
	}
	for _, signature := range entity.Signatures {
		if err := signature.Serialize(&encoded); err != nil {
			t.Fatal(err)
		}
	}
	for _, identity := range entity.Identities {
		if err := identity.UserId.Serialize(&encoded); err != nil {
			t.Fatal(err)
		}
		for _, signature := range identity.Signatures {
			if err := signature.Serialize(&encoded); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, subkey := range entity.Subkeys {
		if err := subkey.PublicKey.Serialize(&encoded); err != nil {
			t.Fatal(err)
		}
		for _, signature := range subkey.Revocations {
			if err := signature.Serialize(&encoded); err != nil {
				t.Fatal(err)
			}
		}
		if err := subkey.Sig.Serialize(&encoded); err != nil {
			t.Fatal(err)
		}
		if subkey.PublicKey.KeyId == subkeyID {
			if err := additional.Serialize(&encoded); err != nil {
				t.Fatal(err)
			}
		}
	}
	return encoded.Bytes()
}

func makeHistoricalV4SignatureFixture(t *testing.T, name string, keyCreated, signedAt time.Time) (*openpgp.Entity, []byte, []byte) {
	t.Helper()
	entity, err := openpgp.NewEntity("Historical "+name, "", name+"@example.invalid", &packet.Config{
		Time:    func() time.Time { return keyCreated },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed := []byte("historical rpm signature fixture: " + name)
	var detached bytes.Buffer
	if err := openpgp.DetachSign(&detached, entity, bytes.NewReader(signed), &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return signedAt },
	}); err != nil {
		t.Fatal(err)
	}
	return entity, signed, detached.Bytes()
}

func publicV4Keyring(t *testing.T, entity *openpgp.Entity) openpgp.EntityList {
	t.Helper()
	var encoded bytes.Buffer
	if err := entity.Serialize(&encoded); err != nil {
		t.Fatal(err)
	}
	keyring, err := openpgp.ReadKeyRing(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(keyring) != 1 {
		t.Fatalf("parsed public key entities=%d, want 1", len(keyring))
	}
	return keyring
}

func TestVerifyEmbeddedRPMSignaturesRejectsHeaderAndPayloadTampering(t *testing.T) {
	data := readPGDGRPMFixture(t)
	keyring := readPGDGPackageKeyring(t)
	layout := testRPMVerificationLayout(t, data)

	headerTampered := append([]byte(nil), data...)
	digest := []byte(strings.ToLower(layout.payloadDigests[0]))
	offset := bytes.Index(headerTampered[layout.mainHeaderStart:layout.mainHeaderEnd], digest)
	if offset < 0 {
		t.Fatalf("payload digest %q is absent from signed main header", digest)
	}
	headerTampered[int(layout.mainHeaderStart)+offset] ^= 1 // 0..9/a..f remains hexadecimal for this fixture.
	_, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(headerTampered), keyring, rpmSignatureVerificationTime)
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "not valid under the trusted keyring") {
		t.Fatalf("signed-header tamper error=%v", err)
	}

	payloadTampered := append([]byte(nil), data...)
	if layout.mainHeaderEnd >= int64(len(payloadTampered)) {
		t.Fatal("real signed fixture contains no payload")
	}
	payloadTampered[len(payloadTampered)-1] ^= 1
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(payloadTampered), keyring, rpmSignatureVerificationTime)
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "payload digest mismatch") {
		t.Fatalf("payload tamper error=%v", err)
	}
}

func TestVerifyEmbeddedRPMSignaturesRejectsUntrustedAndUnsignedPackages(t *testing.T) {
	data := readPGDGRPMFixture(t)
	untrusted, err := openpgp.NewEntity("Untrusted", "", "untrusted@example.invalid", &packet.Config{
		Time:    func() time.Time { return rpmSignatureVerificationTime.Add(-time.Hour) },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data), openpgp.EntityList{untrusted}, rpmSignatureVerificationTime)
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "trusted keyring") {
		t.Fatalf("untrusted signer error=%v", err)
	}

	unsigned := filepath.Join(t.TempDir(), "unsigned.rpm")
	writeRPMFixture(t, unsigned, "unsigned-crypto")
	file, openErr := os.Open(unsigned)
	if openErr != nil {
		t.Fatal(openErr)
	}
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), file, readPGDGPackageKeyring(t), rpmSignatureVerificationTime)
	closeErr := file.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(err, ErrRPMPackageSignature) || !errors.Is(err, ErrEmbeddedSignature) {
		t.Fatalf("unsigned RPM error=%v", err)
	}
}

func TestVerifyEmbeddedRPMSignaturesLegacyPacketCoversHeaderAndPayload(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "legacy-signed.rpm")
	writeRPMFixture(t, filename, "legacy-signed")
	unsigned, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	// writeRPMFixture emits the canonical empty 16-byte signature header, so
	// the original main header begins after the 96-byte lead at offset 112.
	const unsignedMainHeaderStart = 112
	if len(unsigned) <= unsignedMainHeaderStart {
		t.Fatalf("unsigned fixture is only %d bytes", len(unsigned))
	}
	entity, err := openpgp.NewEntity("Legacy RPM", "", "legacy-rpm@example.invalid", &packet.Config{
		Time:    func() time.Time { return rpmSignatureVerificationTime.Add(-time.Hour) },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(unsigned[unsignedMainHeaderStart:]), &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return rpmSignatureVerificationTime.Add(-time.Minute) },
	}); err != nil {
		t.Fatal(err)
	}
	insertFixtureSignatureTag(t, filename, 1002, signature.Bytes())
	signed, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(signed), openpgp.EntityList{entity}, rpmSignatureVerificationTime)
	if err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 1 || proofs[0].HeaderTagID != 1002 || proofs[0].Coverage != RPMSignatureCoverageHeaderPayload ||
		proofs[0].SignedBytes != int64(len(unsigned)-unsignedMainHeaderStart) || proofs[0].PayloadDigest != "" {
		t.Fatalf("legacy signature proof=%+v unsigned_bytes=%d", proofs, len(unsigned))
	}

	tampered := append([]byte(nil), signed...)
	tampered[len(tampered)-1] ^= 1
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(tampered), openpgp.EntityList{entity}, rpmSignatureVerificationTime)
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "not valid under the trusted keyring") {
		t.Fatalf("legacy payload tamper error=%v", err)
	}
}

func TestVerifyEmbeddedRPMSignaturesRejectsSignatureBeyondObservationClockSkew(t *testing.T) {
	const mainHeaderStart = 112
	entity, err := openpgp.NewEntity("Future RPM", "", "future-rpm@example.invalid", &packet.Config{
		Time:    func() time.Time { return rpmSignatureVerificationTime.Add(-time.Hour) },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	signAt := func(name string, at time.Time) []byte {
		t.Helper()
		filename := filepath.Join(t.TempDir(), name+".rpm")
		writeRPMFixture(t, filename, name)
		unsigned, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		var signature bytes.Buffer
		if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(unsigned[mainHeaderStart:]), &packet.Config{
			DefaultHash: crypto.SHA256,
			Time:        func() time.Time { return at },
		}); err != nil {
			t.Fatal(err)
		}
		insertFixtureSignatureTag(t, filename, 1002, signature.Bytes())
		signed, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	boundary := signAt("clock-skew-boundary", rpmSignatureVerificationTime.Add(MaxRPMSignatureClockSkew))
	if _, err := VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(boundary), openpgp.EntityList{entity}, rpmSignatureVerificationTime); err != nil {
		t.Fatalf("signature at documented clock-skew boundary: %v", err)
	}
	future := rpmSignatureVerificationTime.Add(MaxRPMSignatureClockSkew + time.Second)
	signed := signAt("beyond-clock-skew", future)
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(signed), openpgp.EntityList{entity}, rpmSignatureVerificationTime)
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "later than observation") {
		t.Fatalf("future RPM signature error=%v", err)
	}
}

func TestVerifyEmbeddedRPMSignaturesRejectsHeaderOnlySignatureWithoutPayloadDigest(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "incomplete-header-signature.rpm")
	writeRPMFixture(t, filename, "incomplete-header-signature")
	unsigned, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	const mainHeaderStart = 112
	indexCount := int(binary.BigEndian.Uint32(unsigned[mainHeaderStart+8 : mainHeaderStart+12]))
	storeBytes := int(binary.BigEndian.Uint32(unsigned[mainHeaderStart+12 : mainHeaderStart+16]))
	mainHeaderEnd := mainHeaderStart + 16 + indexCount*16 + storeBytes
	if mainHeaderEnd >= len(unsigned) {
		t.Fatalf("invalid unsigned fixture header end %d for %d bytes", mainHeaderEnd, len(unsigned))
	}
	entity, err := openpgp.NewEntity("Modern RPM", "", "modern-rpm@example.invalid", &packet.Config{
		Time:    func() time.Time { return rpmSignatureVerificationTime.Add(-time.Hour) },
		RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := openpgp.DetachSign(&signature, entity, bytes.NewReader(unsigned[mainHeaderStart:mainHeaderEnd]), &packet.Config{
		DefaultHash: crypto.SHA256,
		Time:        func() time.Time { return rpmSignatureVerificationTime.Add(-time.Minute) },
	}); err != nil {
		t.Fatal(err)
	}
	insertFixtureSignatureTag(t, filename, 268, signature.Bytes())
	signed, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), bytes.NewReader(signed), openpgp.EntityList{entity}, rpmSignatureVerificationTime)
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "no trusted embedded signature authenticates the RPM payload") {
		t.Fatalf("header-only signature without payload digest error=%v", err)
	}
}

func readPGDGRPMFixture(t *testing.T) []byte {
	t.Helper()
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func readPGDGPackageKeyring(t *testing.T) openpgp.KeyRing {
	t.Helper()
	encoded, err := os.ReadFile("../../test/compat/testdata/PGDG-RPM-GPG-KEY-RHEL-nonfree.asc")
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := ParseRPMPackageKeyring(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if keyring == nil {
		t.Fatal("PGDG package key fixture is empty")
	}
	return keyring
}

func readHistoricalCentOSKeyring(t *testing.T, filenames ...string) openpgp.EntityList {
	t.Helper()
	var keyring openpgp.EntityList
	for _, filename := range filenames {
		encoded, err := os.ReadFile(filename)
		if err != nil {
			t.Fatal(err)
		}
		entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(encoded))
		if err != nil {
			t.Fatalf("parse %s: %v", filename, err)
		}
		keyring = append(keyring, entities...)
	}
	if len(keyring) == 0 {
		t.Fatal("historical CentOS keyring is empty")
	}
	return keyring
}

func testRPMVerificationLayout(t *testing.T, data []byte) rpmVerificationLayout {
	t.Helper()
	reader := bytes.NewReader(data)
	if _, err := inspectEmbeddedRPMSignaturePackets(context.Background(), reader); err != nil {
		t.Fatal(err)
	}
	mainHeaderStart, err := reader.Seek(0, io.SeekCurrent)
	if err != nil {
		t.Fatal(err)
	}
	layout, err := inspectRPMVerificationLayout(context.Background(), reader, mainHeaderStart)
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

func TestInspectEmbeddedRPMSignaturesRecordsModernPackageMetadata(t *testing.T) {
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := InspectEmbeddedRPMSignatures(context.Background(), bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(signatures) == 0 {
		t.Fatal("signed RPM produced no embedded signature metadata")
	}
	modern := false
	for _, signature := range signatures {
		if signature.PacketSHA256 == "" || signature.PacketSize <= 0 ||
			(signature.PacketVersion != 3 && signature.PacketVersion != 4) ||
			signature.PublicKeyAlgorithm == 0 || signature.HashAlgorithm == 0 {
			t.Fatalf("incomplete embedded signature metadata: %+v", signature)
		}
		if signature.HeaderTagID == 267 && signature.PublicKeyAlgorithm != 17 {
			t.Fatalf("DSA tag metadata=%+v", signature)
		}
		if signature.HeaderTagID == 268 && signature.PublicKeyAlgorithm != 1 && signature.PublicKeyAlgorithm != 3 {
			t.Fatalf("RSA tag metadata=%+v", signature)
		}
		modern = modern || signature.HeaderTagID == 267 || signature.HeaderTagID == 268
	}
	if !modern {
		t.Fatalf("PGDG fixture did not exercise modern RSA/DSA RPM signature tags: %+v", signatures)
	}
}

func TestInspectEmbeddedRPMSignaturesRejectsUnsignedAndMalformedPackets(t *testing.T) {
	unsigned := filepath.Join(t.TempDir(), "unsigned.rpm")
	writeRPMFixture(t, unsigned, "unsigned")
	file, err := os.Open(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	_, inspectErr := InspectEmbeddedRPMSignatures(context.Background(), file)
	closeErr := file.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(inspectErr, ErrEmbeddedSignature) || !strings.Contains(inspectErr.Error(), "no PGP, GPG, RSA, or DSA") {
		t.Fatalf("unsigned RPM error=%v", inspectErr)
	}

	malformed := filepath.Join(t.TempDir(), "malformed-signature.rpm")
	writeRPMFixture(t, malformed, "malformed")
	insertFixtureSignatureTag(t, malformed, 268, []byte{0xc2, 10, 4})
	file, err = os.Open(malformed)
	if err != nil {
		t.Fatal(err)
	}
	_, inspectErr = InspectEmbeddedRPMSignatures(context.Background(), file)
	closeErr = file.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(inspectErr, ErrEmbeddedSignature) || !strings.Contains(inspectErr.Error(), "length") {
		t.Fatalf("malformed RPM signature error=%v", inspectErr)
	}
}

func TestInspectEmbeddedRPMSignaturesParsesModernDSATag(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "dsa-tag.rpm")
	writeRPMFixture(t, filename, "dsa-tag")
	// Structurally valid OpenPGP v4 DSA signature packet with two one-bit MPIs.
	body := []byte{4, 0, 17, 8, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1}
	packet := append([]byte{0xc2, byte(len(body))}, body...)
	insertFixtureSignatureTag(t, filename, 267, packet)
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	signatures, inspectErr := InspectEmbeddedRPMSignatures(context.Background(), file)
	closeErr := file.Close()
	if inspectErr != nil || closeErr != nil {
		t.Fatalf("inspect DSA tag: signatures=%+v inspect=%v close=%v", signatures, inspectErr, closeErr)
	}
	if len(signatures) != 1 || signatures[0].HeaderTagID != 267 || signatures[0].PublicKeyAlgorithm != 17 || signatures[0].HashAlgorithm != 8 {
		t.Fatalf("DSA signature metadata=%+v", signatures)
	}
}

func TestInspectEmbeddedRPMSignaturesOrdersLegacyAndModernTagsDeterministically(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "multi-signature-tag.rpm")
	writeRPMFixture(t, filename, "multi-signature-tag")
	rsaPacket := testV4SignaturePacket(0, 1, nil, nil)
	insertFixtureSignatureTags(t, filename, []fixtureSignatureTag{
		{id: 1002, packet: rsaPacket}, // Deliberately reverse canonical order.
		{id: 268, packet: rsaPacket},
	})
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	signatures, inspectErr := InspectEmbeddedRPMSignatures(context.Background(), file)
	closeErr := file.Close()
	if inspectErr != nil || closeErr != nil {
		t.Fatalf("inspect mixed signature tags: signatures=%+v inspect=%v close=%v", signatures, inspectErr, closeErr)
	}
	if len(signatures) != 2 || signatures[0].HeaderTagID != 268 || signatures[1].HeaderTagID != 1002 {
		t.Fatalf("mixed signature order=%+v", signatures)
	}
	duplicate := filepath.Join(t.TempDir(), "duplicate-signature-tag.rpm")
	writeRPMFixture(t, duplicate, "duplicate-signature-tag")
	insertFixtureSignatureTags(t, duplicate, []fixtureSignatureTag{{id: 268, packet: rsaPacket}, {id: 268, packet: rsaPacket}})
	file, err = os.Open(duplicate)
	if err != nil {
		t.Fatal(err)
	}
	_, inspectErr = InspectEmbeddedRPMSignatures(context.Background(), file)
	closeErr = file.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(inspectErr, ErrEmbeddedSignature) || !strings.Contains(inspectErr.Error(), "duplicate header tag") {
		t.Fatalf("duplicate signature tag error=%v", inspectErr)
	}
}

func TestOpenPGPSignatureRequiresBinaryDocumentType(t *testing.T) {
	v4 := testV4SignaturePacket(0, 17, nil, nil)
	if _, _, _, _, err := parseOpenPGPSignaturePacket(v4); err != nil {
		t.Fatalf("valid v4 signature: %v", err)
	}
	v4[3] = 1 // Packet header occupies two bytes; body[1] is signature type.
	if _, _, _, _, err := parseOpenPGPSignaturePacket(v4); err == nil || !strings.Contains(err.Error(), "v4") {
		t.Fatalf("non-binary v4 signature type error=%v", err)
	}
	v3 := testV3SignaturePacket(0)
	if _, _, _, _, err := parseOpenPGPSignaturePacket(v3); err != nil {
		t.Fatalf("valid v3 signature: %v", err)
	}
	v3[4] = 1 // Old-format two-byte packet header; body[2] is signature type.
	if _, _, _, _, err := parseOpenPGPSignaturePacket(v3); err == nil || !strings.Contains(err.Error(), "v3") {
		t.Fatalf("non-binary v3 signature type error=%v", err)
	}
}

func TestOpenPGPIssuerSubpacketBoundaries(t *testing.T) {
	keyID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	type16 := testSignatureSubpacket(16, keyID)
	if got, err := signatureIssuerKeyID(type16); err != nil || got != "0102030405060708" {
		t.Fatalf("type16 issuer=%q err=%v", got, err)
	}
	fingerprint := append([]byte{4}, bytes.Repeat([]byte{0xaa}, 12)...)
	fingerprint = append(fingerprint, keyID...)
	type33 := testSignatureSubpacket(33, fingerprint)
	if got, err := signatureIssuerKeyID(type33); err != nil || got != "0102030405060708" {
		t.Fatalf("type33 issuer=%q err=%v", got, err)
	}
	wrongVersion := append([]byte(nil), fingerprint...)
	wrongVersion[0] = 99
	wrongLength := append([]byte(nil), fingerprint[:len(fingerprint)-1]...)
	for name, encoded := range map[string][]byte{
		"type16-short":        testSignatureSubpacket(16, keyID[:7]),
		"type33-version":      testSignatureSubpacket(33, wrongVersion),
		"type33-length":       testSignatureSubpacket(33, wrongLength),
		"partial-subpacket":   {224},
		"truncated-subpacket": {10, 16, 1},
	} {
		if _, err := signatureIssuerKeyID(encoded); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	otherID := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	conflict := append(append([]byte(nil), type16...), testSignatureSubpacket(16, otherID)...)
	if _, err := signatureIssuerKeyID(conflict); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("same-area issuer conflict error=%v", err)
	}
	crossArea := testV4SignaturePacket(0, 17, type16, testSignatureSubpacket(16, otherID))
	if _, _, _, _, err := parseOpenPGPSignaturePacket(crossArea); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("hashed/unhashed issuer conflict error=%v", err)
	}
}

func TestOpenPGPSignatureCreationTimeMustBeUniqueAndHashed(t *testing.T) {
	created := time.Date(2020, 9, 13, 12, 26, 40, 0, time.UTC)
	createdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(createdBytes, uint32(created.Unix()))
	creation := testSignatureSubpacket(2, createdBytes)
	packet := testV4SignaturePacket(0, 1, creation, nil)
	got, err := parseOpenPGPSignatureCreationTime(packet)
	if err != nil || !got.Equal(created) {
		t.Fatalf("hashed creation time=%s err=%v", got, err)
	}
	for name, packet := range map[string][]byte{
		"unhashed":  testV4SignaturePacket(0, 1, nil, creation),
		"duplicate": testV4SignaturePacket(0, 1, append(append([]byte(nil), creation...), creation...), nil),
		"malformed": testV4SignaturePacket(0, 1, testSignatureSubpacket(2, []byte{1, 2, 3}), nil),
	} {
		if _, err := parseOpenPGPSignatureCreationTime(packet); err == nil {
			t.Errorf("%s creation-time packet accepted", name)
		}
	}
	missing, err := parseOpenPGPSignatureCreationTime(testV4SignaturePacket(0, 1, nil, nil))
	if err != nil || !missing.IsZero() {
		t.Fatalf("missing creation time=%s err=%v", missing, err)
	}
	v3 := testV3SignaturePacket(0)
	binary.BigEndian.PutUint32(v3[5:9], uint32(created.Unix()))
	got, err = parseOpenPGPSignatureCreationTime(v3)
	if err != nil || !got.Equal(created) {
		t.Fatalf("v3 creation time=%s err=%v", got, err)
	}
}

func TestVerifyEmbeddedRPMSignaturesRejectsMissingAuthenticatedCreationTime(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "missing-signature-time.rpm")
	writeRPMFixture(t, filename, "missing-signature-time")
	insertFixtureSignatureTag(t, filename, 1002, testV4SignaturePacket(0, 1, nil, nil))
	file, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyEmbeddedRPMSignatures(context.Background(), file, readPGDGPackageKeyring(t), rpmSignatureVerificationTime)
	closeErr := file.Close()
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if !errors.Is(err, ErrRPMPackageSignature) || !strings.Contains(err.Error(), "no authenticated signature creation time") {
		t.Fatalf("missing signature creation time error=%v", err)
	}
}

func TestOpenPGPPacketLengthAndMPIBoundaries(t *testing.T) {
	body := bytes.Repeat([]byte{0x42}, 200)
	encodings := map[string][]byte{
		"old-one":           append([]byte{0x88, byte(len(body))}, body...),
		"old-two":           append(append([]byte{0x89}, uint16Bytes(uint16(len(body)))...), body...),
		"old-four":          append(append([]byte{0x8a}, uint32Bytes(uint32(len(body)))...), body...),
		"old-indeterminate": append([]byte{0x8b}, body...),
		"new-two":           append([]byte{0xc2, 192, 8}, body...),
		"new-five":          append(append([]byte{0xc2, 255}, uint32Bytes(uint32(len(body)))...), body...),
	}
	for name, encoded := range encodings {
		got, err := unwrapOpenPGPSignaturePacket(encoded)
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("%s body=%d err=%v", name, len(got), err)
		}
	}
	shortBody := []byte{1, 2, 3}
	if got, err := unwrapOpenPGPSignaturePacket(append([]byte{0xc2, 3}, shortBody...)); err != nil || !bytes.Equal(got, shortBody) {
		t.Fatalf("new one-octet length body=%x err=%v", got, err)
	}
	invalidPackets := [][]byte{
		{0x00, 0}, {0xc1, 0}, {0x89, 0}, {0x8a, 0, 0}, {0xc2, 192}, {0xc2, 224}, {0xc2, 255, 0},
		{0xc2, 1, 1, 2},
	}
	for _, encoded := range invalidPackets {
		if _, err := unwrapOpenPGPSignaturePacket(encoded); err == nil {
			t.Errorf("invalid packet accepted: %x", encoded)
		}
	}
	for name, test := range map[string]struct {
		algorithm int
		material  []byte
	}{
		"unsupported":   {2, []byte{0, 1, 1}},
		"truncated":     {1, []byte{0, 8}},
		"zero":          {1, []byte{0, 0, 0}},
		"noncanonical":  {1, []byte{0, 8, 1}},
		"trailing":      {1, []byte{0, 1, 1, 0}},
		"missing-dsa-s": {17, []byte{0, 1, 1}},
	} {
		if err := validateSignatureMaterial(test.algorithm, test.material); err == nil {
			t.Errorf("%s MPI accepted", name)
		}
	}
}

type cancelAfterRead struct {
	reader io.Reader
	cancel context.CancelFunc
	done   bool
}

func (r *cancelAfterRead) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	if !r.done {
		r.done = true
		r.cancel()
	}
	return n, err
}

func TestInspectEmbeddedRPMSignaturesHonorsContextWithoutReadingPayload(t *testing.T) {
	encoded, err := os.ReadFile("../cli/testdata/pgdg-redhat-nonfree-repo.rpm.b64")
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := InspectEmbeddedRPMSignatures(ctx, bytes.NewReader(data)); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel error=%v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	reader := &cancelAfterRead{reader: bytes.NewReader(data), cancel: cancel}
	if _, err := InspectEmbeddedRPMSignatures(ctx, reader); !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-header cancel error=%v", err)
	}
}

func FuzzParseOpenPGPSignaturePacket(f *testing.F) {
	f.Add(testV4SignaturePacket(0, 17, nil, nil))
	f.Add(testV3SignaturePacket(0))
	f.Add([]byte{0xc2, 224})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _, _ = parseOpenPGPSignaturePacket(data)
	})
}

func testV4SignaturePacket(signatureType byte, algorithm byte, hashed, unhashed []byte) []byte {
	body := []byte{4, signatureType, algorithm, 8}
	body = append(body, uint16Bytes(uint16(len(hashed)))...)
	body = append(body, hashed...)
	body = append(body, uint16Bytes(uint16(len(unhashed)))...)
	body = append(body, unhashed...)
	body = append(body, 0, 0)
	body = append(body, 0, 1, 1)
	if algorithm == 17 || algorithm == 19 || algorithm == 22 {
		body = append(body, 0, 1, 1)
	}
	return append([]byte{0xc2, byte(len(body))}, body...)
}

func testV3SignaturePacket(signatureType byte) []byte {
	body := make([]byte, 19)
	body[0], body[1], body[2] = 3, 5, signatureType
	copy(body[7:15], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	body[15], body[16] = 1, 8
	body = append(body, 0, 1, 1)
	return append([]byte{0x88, byte(len(body))}, body...)
}

func testSignatureSubpacket(tag byte, payload []byte) []byte {
	packet := append([]byte{tag}, payload...)
	return append([]byte{byte(len(packet))}, packet...)
}

func uint16Bytes(value uint16) []byte {
	result := make([]byte, 2)
	binary.BigEndian.PutUint16(result, value)
	return result
}

func uint32Bytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}

type fixtureSignatureTag struct {
	id     uint32
	packet []byte
}

func insertFixtureSignatureTag(t *testing.T, filename string, tagID uint32, packet []byte) {
	t.Helper()
	insertFixtureSignatureTags(t, filename, []fixtureSignatureTag{{id: tagID, packet: packet}})
}

func insertFixtureSignatureTags(t *testing.T, filename string, tags []fixtureSignatureTag) {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 112 {
		t.Fatal("RPM fixture is too short")
	}
	descriptor := make([]byte, 16)
	copy(descriptor, []byte{0x8e, 0xad, 0xe8, 1})
	binary.BigEndian.PutUint32(descriptor[8:12], uint32(len(tags)))
	indexes := make([]byte, len(tags)*16)
	var store bytes.Buffer
	for i, tag := range tags {
		offset := i * 16
		binary.BigEndian.PutUint32(indexes[offset:offset+4], tag.id)
		binary.BigEndian.PutUint32(indexes[offset+4:offset+8], 7) // RPM_BIN_TYPE.
		binary.BigEndian.PutUint32(indexes[offset+8:offset+12], uint32(store.Len()))
		binary.BigEndian.PutUint32(indexes[offset+12:offset+16], uint32(len(tag.packet)))
		store.Write(tag.packet)
	}
	binary.BigEndian.PutUint32(descriptor[12:16], uint32(store.Len()))
	padding := make([]byte, (8-store.Len()%8)%8)
	updated := bytes.Join([][]byte{data[:96], descriptor, indexes, store.Bytes(), padding, data[112:]}, nil)
	if err := os.WriteFile(filename, updated, 0o644); err != nil {
		t.Fatal(err)
	}
}
