package cli

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const materializeKeyLimit = 16 << 20

// deterministicMaterializeKey deliberately disables go-crypto's randomized
// v4 salt notation. A materialization is a reproducible derived build from an
// immutable ref; changing only signature salt would make an otherwise exact
// offline tgz non-reproducible. Signature creation time is still authenticated
// and comes from the canonical commit, and every output is self-verified.
type deterministicMaterializeKey struct {
	entities openpgp.EntityList
	signer   *openpgp.Entity
	config   packet.Config
}

func newDeterministicMaterializeKey(key, passphrase []byte, at time.Time) (*deterministicMaterializeKey, error) {
	if len(key) == 0 || len(key) > materializeKeyLimit || at.IsZero() {
		return nil, errors.New("invalid deterministic materialization signing key")
	}
	material := append([]byte(nil), key...)
	defer clearSecret(material)
	var entities openpgp.EntityList
	var err error
	if bytes.HasPrefix(bytes.TrimSpace(material), []byte("-----BEGIN PGP")) {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(material))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(material))
	}
	if err != nil || len(entities) != 1 || entities[0] == nil || entities[0].PrivateKey == nil {
		return nil, errors.New("invalid deterministic materialization signing key")
	}
	entity := entities[0]
	if entity.PrivateKey.Encrypted {
		if len(passphrase) == 0 || entity.PrivateKey.Decrypt(passphrase) != nil {
			return nil, errors.New("cannot unlock deterministic materialization signing key")
		}
	}
	for index := range entity.Subkeys {
		private := entity.Subkeys[index].PrivateKey
		if private != nil && private.Encrypted {
			if len(passphrase) == 0 || private.Decrypt(passphrase) != nil {
				return nil, errors.New("cannot unlock deterministic materialization signing key")
			}
		}
	}
	if signingKey, ok := entity.SigningKey(at.UTC()); !ok || signingKey.PrivateKey == nil || signingKey.PrivateKey.Encrypted {
		return nil, errors.New("deterministic materialization signing key is not usable at the canonical commit time")
	}
	randomized := false
	return &deterministicMaterializeKey{
		entities: entities,
		signer:   entity,
		config: packet.Config{
			DefaultHash:                           crypto.SHA256,
			Time:                                  func() time.Time { return at.UTC() },
			NonDeterministicSignaturesViaNotation: &randomized,
		},
	}, nil
}

func (key *deterministicMaterializeKey) Sign(ctx context.Context, message io.Reader, signature io.Writer) error {
	if key == nil || key.signer == nil || message == nil || signature == nil {
		return errors.New("invalid deterministic materialization signing request")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := openpgp.ArmoredDetachSign(signature, key.signer, &materializeContextReader{ctx: ctx, reader: message}, &key.config); err != nil {
		return errors.New("deterministic materialization signing failed")
	}
	return nil
}

func (key *deterministicMaterializeKey) Verify(ctx context.Context, message io.Reader, signature io.Reader) error {
	if key == nil || len(key.entities) != 1 || message == nil || signature == nil {
		return errors.New("invalid deterministic materialization verification request")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(key.entities, &materializeContextReader{ctx: ctx, reader: message}, signature, &key.config); err != nil {
		return errors.New("deterministic materialization signature verification failed")
	}
	return nil
}

func (key *deterministicMaterializeKey) clearSign(message []byte) ([]byte, error) {
	if key == nil || key.signer == nil {
		return nil, errors.New("invalid deterministic materialization signing request")
	}
	signingKey, ok := key.signer.SigningKey(key.config.Now())
	if !ok || signingKey.PrivateKey == nil || signingKey.PrivateKey.Encrypted {
		return nil, errors.New("deterministic materialization signing key is unavailable")
	}
	var encoded bytes.Buffer
	plaintext, err := clearsign.Encode(&encoded, signingKey.PrivateKey, &key.config)
	if err != nil {
		return nil, errors.New("deterministic materialization clear-sign failed")
	}
	if _, err := plaintext.Write(message); err != nil {
		_ = plaintext.Close()
		return nil, err
	}
	if err := plaintext.Close(); err != nil {
		return nil, errors.New("deterministic materialization clear-sign failed")
	}
	return encoded.Bytes(), nil
}

func rewriteDeterministicAPTSignatures(ctx context.Context, archiveRoot, suite string, key *deterministicMaterializeKey) error {
	releasePath := filepath.Join(archiveRoot, "dists", suite, "Release")
	release, err := os.ReadFile(releasePath)
	if err != nil {
		return err
	}
	var detached bytes.Buffer
	if err := key.Sign(ctx, bytes.NewReader(release), &detached); err != nil {
		return err
	}
	inRelease, err := key.clearSign(release)
	if err != nil {
		return err
	}
	if err := key.Verify(ctx, bytes.NewReader(release), bytes.NewReader(detached.Bytes())); err != nil {
		return err
	}
	if err := writeDerivedMetadata(filepath.Join(archiveRoot, "dists", suite, "Release.gpg"), detached.Bytes()); err != nil {
		return err
	}
	if err := writeDerivedMetadata(filepath.Join(archiveRoot, "dists", suite, "InRelease"), inRelease); err != nil {
		return err
	}
	return nil
}

func writeDerivedMetadata(destination string, contents []byte) error {
	directory := filepath.Dir(destination)
	temporary, err := os.CreateTemp(directory, ".sow-materialize-signature-")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		if !keep {
			temporary.Close()
			os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o644); err != nil {
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := errors.Join(temporary.Sync(), temporary.Close()); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return fmt.Errorf("install deterministic derived signature: %w", err)
	}
	if err := syncLocalDirectory(directory); err != nil {
		return err
	}
	keep = true
	return nil
}

type materializeContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *materializeContextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}
