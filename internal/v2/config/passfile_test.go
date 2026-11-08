package config

import (
	"strings"
	"testing"
)

func TestPassfileConfigurationAndLegacyReferences(t *testing.T) {
	for _, stanza := range []string{
		"rpm:\n        packages:\n          key: agent://0123456789ABCDEF\n          passfile: secrets/rpm-pass",
		"rpm:\n        metadata:\n          key: agent://0123456789ABCDEF\n          passfile: /run/secrets/rpm-pass",
		"deb:\n        metadata:\n          key: keys/signing.asc\n          passfile: secrets/apt-pass",
		"deb:\n        metadata:\n          key: agent://0123456789ABCDEF\n          passphrase: env://OLD_PASS",
	} {
		input := "schema: sow/v3\nrepos:\n  demo:\n    signing:\n      " + stanza + "\n"
		cfg, err := Parse([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(encoded); err != nil {
			t.Fatalf("roundtrip: %v", err)
		}
		view, err := EffectiveView(cfg, ViewOptions{})
		if err != nil {
			t.Fatal(err)
		}
		raw, effective := cfg.Repositories["demo"].Signing, view.Repositories["demo"].Signing
		if raw.RPM.Packages.PassFile != effective.RPM.Packages.PassFile {
			t.Fatal("package passfile disappeared")
		}
		if raw.RPM.Metadata.Key != "" && raw.RPM.Metadata.PassFile != effective.RPM.Metadata.PassFile {
			t.Fatal("RPM metadata passfile disappeared")
		}
		if raw.DEB.Metadata.Key != "" && raw.DEB.Metadata.PassFile != effective.DEB.Metadata.PassFile {
			t.Fatal("APT metadata passfile disappeared")
		}
	}
}

func TestPassfileConfigurationRejectsConflictsAndInvalidPaths(t *testing.T) {
	for _, tc := range []struct{ stanza, want string }{
		{"rpm:\n        metadata:\n          key: keys/signing.asc\n          passfile: a\n          passphrase: env://OLD_PASS", "mutually exclusive"},
		{"deb:\n        metadata:\n          key: keys/signing.asc\n          passfile: a\n          passphrase: file://b", "mutually exclusive"},
		{"rpm:\n        packages:\n          passfile: a", "passfile requires key"},
		{"deb:\n        metadata:\n          passfile: a", "passfile requires key"},
		{"rpm:\n        metadata:\n          key: keys/signing.asc\n          passfile: '   '", "non-empty path"},
		{"rpm:\n        packages:\n          key: agent://0123456789ABCDEF\n          passfile: \"a\\nb\"", "line breaks"},
		{"rpm:\n        metadata:\n          key: keys/signing.asc\n          passfile: file:///run/secrets/gpg", "not a URI"},
	} {
		_, err := Parse([]byte("schema: sow/v3\nrepos:\n  demo:\n    signing:\n      " + tc.stanza + "\n"))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("configuration error=%v, want %s", err, tc.want)
		}
	}
}
