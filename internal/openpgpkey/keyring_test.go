package openpgpkey

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestReadPreservesCompleteBundles(t *testing.T) {
	created := time.Unix(1_700_000_000, 0).UTC()
	var entities openpgp.EntityList
	var binary, separate bytes.Buffer
	for _, name := range []string{"first", "second"} {
		entity, err := openpgp.NewEntity(name, "", name+"@example.invalid", &packet.Config{RSABits: 1024, Time: func() time.Time { return created }})
		if err != nil {
			t.Fatal(err)
		}
		entities = append(entities, entity)
		if err := entity.Serialize(&binary); err != nil {
			t.Fatal(err)
		}
		separate.Write(publicArmor(t, openpgp.EntityList{entity}))
		separate.WriteString("\r\n \t")
	}
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "binary", data: binary.Bytes()},
		{name: "one armor block", data: publicArmor(t, entities)},
		{name: "separate armor blocks", data: separate.Bytes()},
		{name: "binary with marker packet", data: append(append([]byte(nil), binary.Bytes()...), 0xca, 3, 'P', 'G', 'P')},
		{name: "binary with non-critical packet", data: append(append([]byte(nil), binary.Bytes()...), 0xfd, 1, 0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			parsed, err := Read(test.data)
			if err != nil || len(parsed) != 2 {
				t.Fatalf("bundle entities=%d err=%v", len(parsed), err)
			}
			for i, entity := range parsed {
				if !bytes.Equal(entity.PrimaryKey.Fingerprint, entities[i].PrimaryKey.Fingerprint) {
					t.Fatal("bundle changed a primary identity")
				}
			}
			if _, err := ReadSingle(test.data); err == nil {
				t.Fatal("single-key reader accepted a bundle")
			}
		})
	}
	first := publicArmor(t, entities[:1])
	var firstBinary, malformedSecond bytes.Buffer
	if err := entities[0].Serialize(&firstBinary); err != nil {
		t.Fatal(err)
	}
	// A primary packet without its required identity is a malformed second
	// entity. ReadKeyRing deliberately skips it after the valid first key.
	if err := entities[1].PrimaryKey.Serialize(&malformedSecond); err != nil {
		t.Fatal(err)
	}
	footer := []byte("-----END PGP PUBLIC KEY BLOCK-----")
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "trailing garbage", data: append(append([]byte(nil), first...), []byte("garbage")...)},
		{name: "leading garbage", data: append([]byte("garbage\n"), first...)},
		{name: "missing footer", data: bytes.Replace(first, footer, nil, 1)},
		{name: "wrong footer", data: bytes.Replace(first, footer, []byte("-----END PGP PRIVATE KEY BLOCK-----"), 1)},
		{name: "hidden nested block", data: append([]byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid header\n"), first...)},
		{name: "garbage after checksum", data: bytes.Replace(first, footer, append([]byte("garbage\n"), footer...), 1)},
		{name: "malformed second binary entity", data: append(append([]byte(nil), firstBinary.Bytes()...), malformedSecond.Bytes()...)},
		// A v4 public-key packet with an unsupported algorithm after its
		// creation time must not disappear behind a usable first key.
		{name: "unsupported second binary key", data: append(append([]byte(nil), firstBinary.Bytes()...), 0xc6, 6, 4, 0, 0, 0, 1, 255)},
		{name: "truncated next packet header", data: append(append([]byte(nil), firstBinary.Bytes()...), 0xc6)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Read(test.data); err == nil {
				t.Fatal("reader accepted incomplete key material")
			}
			if _, err := ReadSingle(test.data); err == nil {
				t.Fatal("single-key reader accepted incomplete key material")
			}
		})
	}
}

func publicArmor(t *testing.T, entities openpgp.EntityList) []byte {
	t.Helper()
	var output bytes.Buffer
	writer, err := armor.Encode(&output, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, entity := range entities {
		if err := entity.Serialize(writer); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestReadValidatesIgnoredPacketBoundaries(t *testing.T) {
	created := time.Unix(1_700_000_000, 0).UTC()
	entity, err := openpgp.NewEntity("packet-boundaries", "", "boundaries@example.invalid", &packet.Config{RSABits: 1024, Time: func() time.Time { return created }})
	if err != nil {
		t.Fatal(err)
	}
	var key bytes.Buffer
	if err := entity.Serialize(&key); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		packet []byte
		valid  bool
	}{
		{name: "new one-byte noncritical length", packet: []byte{0xfd, 1, 0}, valid: true},
		{name: "new two-byte noncritical length", packet: append([]byte{0xfd, 192, 0}, make([]byte, 192)...), valid: true},
		{name: "new five-byte noncritical length", packet: []byte{0xfd, 255, 0, 0, 0, 1, 0}, valid: true},
		{name: "new zero-length noncritical packet", packet: []byte{0xfd, 0}, valid: true},
		{name: "new trust packet", packet: []byte{0xcc, 1, 0}, valid: true},
		{name: "new marker packet", packet: []byte{0xca, 3, 'P', 'G', 'P'}, valid: true},
		{name: "old one-byte trust length", packet: []byte{0xb0, 1, 0}, valid: true},
		{name: "old two-byte trust length", packet: []byte{0xb1, 0, 1, 0}, valid: true},
		{name: "old four-byte trust length", packet: []byte{0xb2, 0, 0, 0, 1, 0}, valid: true},
		{name: "old indeterminate trust length", packet: []byte{0xb3, 0}, valid: true},
		{name: "old zero-length indeterminate trust packet", packet: []byte{0xb3}, valid: true},
		{name: "new partial noncritical body", packet: []byte{0xfd, 224, 0, 225, 0, 0, 1, 0}, valid: true},
		{name: "new partial body with empty final chunk", packet: []byte{0xfd, 224, 0, 0}, valid: true},
		{name: "truncated noncritical body", packet: []byte{0xfd, 2, 0}},
		{name: "absent noncritical body", packet: []byte{0xfd, 1}},
		{name: "longer truncated noncritical body", packet: []byte{0xfd, 5, 0}},
		{name: "truncated new two-byte length", packet: []byte{0xfd, 192}},
		{name: "truncated new two-byte body", packet: append([]byte{0xfd, 192, 0}, make([]byte, 191)...)},
		{name: "truncated new five-byte length", packet: []byte{0xfd, 255, 0, 0, 0}},
		{name: "truncated new five-byte body", packet: []byte{0xfd, 255, 0, 0, 0, 2, 0}},
		{name: "truncated trust body", packet: []byte{0xcc, 2, 0}},
		{name: "truncated marker body", packet: []byte{0xca, 3, 'P', 'G'}},
		{name: "truncated old one-byte body", packet: []byte{0xb0, 2, 0}},
		{name: "truncated old two-byte length", packet: []byte{0xb1, 0}},
		{name: "truncated old two-byte body", packet: []byte{0xb1, 0, 2, 0}},
		{name: "truncated old four-byte length", packet: []byte{0xb2, 0, 0, 0}},
		{name: "truncated old four-byte body", packet: []byte{0xb2, 0, 0, 0, 2, 0}},
		{name: "partial body lacks final chunk", packet: []byte{0xfd, 224, 0}},
		{name: "partial body truncated first chunk", packet: []byte{0xfd, 225, 0}},
		{name: "partial body truncated final chunk", packet: []byte{0xfd, 224, 0, 2, 0}},
		{name: "partial body truncated continuation length", packet: []byte{0xfd, 224, 0, 255, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			binary := append(append([]byte(nil), key.Bytes()...), test.packet...)
			var armored bytes.Buffer
			writer, err := armor.Encode(&armored, openpgp.PublicKeyType, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(binary); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			for _, input := range []struct {
				name string
				data []byte
			}{{name: "binary", data: binary}, {name: "armor", data: armored.Bytes()}} {
				t.Run(input.name, func(t *testing.T) {
					for _, read := range []func([]byte) (openpgp.EntityList, error){Read, ReadSingle} {
						entities, err := read(input.data)
						if test.valid {
							if err != nil || len(entities) != 1 || !bytes.Equal(entities[0].PrimaryKey.Fingerprint, entity.PrimaryKey.Fingerprint) {
								t.Fatalf("complete compatible packet rejected: entities=%d err=%v", len(entities), err)
							}
						} else if err == nil {
							t.Fatal("truncated packet was accepted")
						}
					}
				})
			}
		})
	}
}
