package yumrepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestActivateLocalPostGuardFailureRestoresOldGeneration(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	live, staged := filepath.Join(parent, "repodata"), filepath.Join(parent, ".repodata.staged")
	if _, err := Generate(t.Context(), live, Options{ELMajor: 8, Revision: 40, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}}); err != nil {
		t.Fatal(err)
	}
	wanted, err := Generate(t.Context(), staged, Options{ELMajor: 8, Revision: 41, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}})
	if err != nil {
		t.Fatal(err)
	}
	exchanger := NativeDirectoryExchanger{}
	if err := exchanger.Probe(parent); err != nil {
		if errors.Is(err, ErrAtomicUnsupported) {
			t.Skipf("filesystem lacks native directory exchange: %v", err)
		}
		t.Fatal(err)
	}
	rotated := errors.New("trust rotated during activation")
	err = ActivateLocalGuarded(t.Context(), live, staged, CompressionGzip, signer, wanted.RepomdSHA256, exchanger, func(phase ActivationPhase) error {
		if phase == ActivationAfterExchange {
			return rotated
		}
		return nil
	})
	if !errors.Is(err, rotated) {
		t.Fatalf("guarded activation error = %v", err)
	}
	active, err := ValidateDirectory(t.Context(), live, CompressionGzip, signer)
	if err != nil || active.Revision != 40 {
		t.Fatalf("old live generation was not restored: generation=%+v err=%v", active, err)
	}
	rolledBack, err := ValidateDirectory(t.Context(), staged, CompressionGzip, signer)
	if err != nil || rolledBack.Revision != 41 {
		t.Fatalf("rejected generation is not retained at staged: generation=%+v err=%v", rolledBack, err)
	}
}

func TestActivateInitialPostGuardFailureRemovesLiveGeneration(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	live, staged := filepath.Join(parent, "repodata"), filepath.Join(parent, ".repodata.staged")
	wanted, err := Generate(t.Context(), staged, Options{ELMajor: 8, Revision: 50, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}})
	if err != nil {
		t.Fatal(err)
	}
	rotated := errors.New("trust rotated during initial activation")
	err = ActivateInitialLocalGuarded(t.Context(), live, staged, CompressionGzip, signer, wanted.RepomdSHA256, func(phase ActivationPhase) error {
		if phase == ActivationAfterExchange {
			return rotated
		}
		return nil
	})
	if !errors.Is(err, rotated) {
		t.Fatalf("guarded initial activation error = %v", err)
	}
	if _, err := os.Lstat(live); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rejected initial generation remains live: %v", err)
	}
	rolledBack, err := ValidateDirectory(t.Context(), staged, CompressionGzip, signer)
	if err != nil || rolledBack.Revision != 50 {
		t.Fatalf("rejected initial generation is not retained at staged: generation=%+v err=%v", rolledBack, err)
	}
}

func TestActivateInitialCreateOnlyInstallPreservesRacingDestination(t *testing.T) {
	parent := t.TempDir()
	fixture := filepath.Join(parent, "fixture.rpm")
	writeRPMFixture(t, fixture, "fixture")
	signer := testSigner(t)
	live, staged := filepath.Join(parent, "repodata"), filepath.Join(parent, ".repodata.staged")
	wanted, err := Generate(t.Context(), staged, Options{ELMajor: 8, Revision: 60, Signer: signer}, &SliceIterator{Inputs: []PackageInput{{Path: fixture}}})
	if err != nil {
		t.Fatal(err)
	}
	err = ActivateInitialLocalGuarded(context.Background(), live, staged, CompressionGzip, signer, wanted.RepomdSHA256, func(phase ActivationPhase) error {
		if phase != ActivationBeforeExchange {
			return nil
		}
		if err := os.Mkdir(live, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(live, "racing.marker"), []byte("external"), 0o644)
	})
	if err == nil {
		t.Fatal("create-only initial activation accepted a racing destination")
	}
	body, readErr := os.ReadFile(filepath.Join(live, "racing.marker"))
	if readErr != nil || string(body) != "external" {
		t.Fatalf("racing destination was overwritten: body=%q err=%v", body, readErr)
	}
	if _, err := ValidateDirectory(t.Context(), staged, CompressionGzip, signer); err != nil {
		t.Fatalf("staged generation was lost on create-only conflict: %v", err)
	}
}
