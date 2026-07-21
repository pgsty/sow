package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/pgsty/sow/internal/manifest"
	"github.com/pgsty/sow/internal/serving"
	"github.com/pgsty/sow/internal/state"
	"github.com/pgsty/sow/internal/views"
)

// mergeRetainedYUMPackageClosure builds one new immutable serving manifest
// from the current repository tree plus package payloads indexed by the
// target's retained channel generations. Real DNF may resolve the mutable
// mirrorlist again between metadata and payload phases; retaining these
// unindexed hardlinks lets a transaction that read old signed metadata finish
// against a newer generation without changing primary.xml href semantics.
//
// The old package set is reconstructed from each generation's exact canonical
// view commit, never from its full serving manifest. That distinction prevents
// compatibility-only payloads from recursively becoming permanent GC roots.
func mergeRetainedYUMPackageClosure(canonical *state.Store, channel *serving.Channel, previousRetention int, currentManifest, destination, tempDir string) error {
	if previousRetention < 1 {
		return errors.New("YUM generation previous retention must be positive")
	}
	if canonical == nil || channel == nil {
		return errors.New("retained YUM package closure canonical authority is unavailable")
	}
	if err := channel.Validate(); err != nil {
		return err
	}
	pins, err := channel.RetainedGenerationPins()
	if err != nil {
		return err
	}
	// A configuration decrease must take effect on the next derived
	// generation. The old current generation plus at most N of its predecessors
	// close transactions already in flight; older compatibility-only payloads
	// must not leak forward merely because the previous channel retained them.
	if limit := 1 + previousRetention; len(pins) > limit {
		pins = pins[:limit]
	}
	inputs := make([]views.ProjectionInput, 0, len(pins))
	var opened []*os.File
	defer func() {
		for _, file := range opened {
			_ = file.Close()
		}
	}()
	for index, pin := range pins {
		coordinate := serving.GenerationCoordinate{ID: pin.ID, View: channel.View, Repo: channel.Repo, OS: channel.OS, Arch: channel.Arch}
		jsonPath, err := coordinate.JSONPath()
		if err != nil {
			return err
		}
		body, exists, err := readOptionalCanonical(canonical, jsonPath)
		if err != nil || !exists {
			return errors.Join(err, fmt.Errorf("retained YUM generation %s has no canonical record", pin.ID))
		}
		generation, err := serving.DecodeGeneration(body)
		if err != nil {
			return fmt.Errorf("decode retained YUM generation %s: %w", pin.ID, err)
		}
		if generation.ID != pin.ID || generation.ContentSHA256 != pin.ContentSHA256 || generation.ManifestSHA256 != pin.ManifestSHA256 ||
			generation.View != channel.View || generation.Repo != channel.Repo || generation.OS != channel.OS || generation.Arch != channel.Arch || generation.LegacyRoot != channel.LegacyRoot {
			return fmt.Errorf("retained YUM generation %s differs from its channel pin", pin.ID)
		}
		manifestStatePath, err := coordinate.ManifestPath()
		if err != nil {
			return err
		}
		generationManifest, err := canonical.OpenPath(manifestStatePath)
		if err != nil {
			return fmt.Errorf("open retained YUM generation manifest %s: %w", manifestStatePath, err)
		}
		derived, deriveErr := serving.DeriveGeneration(serving.Identity{
			View: generation.View, Repo: generation.Repo, OS: generation.OS, Arch: generation.Arch,
			LegacyRoot: generation.LegacyRoot, RefCommit: generation.RefCommit,
			ConfigSHA256: generation.ConfigSHA256, RepositoryKeySHA256: generation.RepositoryKeySHA256,
		}, generationManifest)
		closeErr := generationManifest.Close()
		if deriveErr != nil || closeErr != nil {
			return errors.Join(deriveErr, closeErr)
		}
		if derived != generation {
			return fmt.Errorf("retained YUM generation %s differs from its canonical manifest", pin.ID)
		}
		if len(generation.RefCommit) != 40 {
			return fmt.Errorf("retained YUM generation %s uses unsupported canonical commit width", pin.ID)
		}
		commit := plumbing.NewHash(generation.RefCommit)
		if commit.IsZero() || commit.String() != generation.RefCommit {
			return fmt.Errorf("retained YUM generation %s has invalid canonical commit", pin.ID)
		}
		viewPath, err := state.ViewPath(generation.View, generation.Repo, generation.OS, generation.Arch)
		if err != nil {
			return err
		}
		reader, err := canonical.OpenPathAt(commit, viewPath)
		if err != nil {
			return fmt.Errorf("open retained YUM view %s at %s: %w", viewPath, commit, err)
		}
		staged := filepath.Join(tempDir, fmt.Sprintf("retained-yum-view-%06d.tsv", index))
		stagedFile, err := os.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			_ = reader.Close()
			return err
		}
		_, copyErr := io.Copy(stagedFile, reader)
		closeErr = errors.Join(reader.Close(), stagedFile.Sync(), stagedFile.Close())
		if copyErr != nil || closeErr != nil {
			return errors.Join(copyErr, closeErr)
		}
		validation, err := os.Open(staged)
		if err != nil {
			return err
		}
		_, validationErr := views.ValidateLeaf(validation, generation.Repo, generation.OS, generation.Arch, generation.View != "stable")
		if validationErr == nil {
			_, validationErr = validation.Seek(0, io.SeekStart)
		}
		if validationErr == nil {
			validationErr = validateRetainedYUMPayloadPaths(validation, generation.LegacyRoot)
		}
		closeErr = validation.Close()
		if validationErr != nil || closeErr != nil {
			return errors.Join(validationErr, closeErr)
		}
		project, err := os.Open(staged)
		if err != nil {
			return err
		}
		opened = append(opened, project)
		inputs = append(inputs, views.ProjectionInput{Label: jsonPath, Reader: project})
	}
	if len(inputs) == 0 {
		return errors.New("retained YUM package closure has no canonical generation pins")
	}
	retainedPath := filepath.Join(tempDir, "retained-yum-packages.tsv")
	retained, err := os.OpenFile(retainedPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, _, projectErr := views.ProjectManifest(inputs, retained)
	closeErr := errors.Join(retained.Sync(), retained.Close())
	if projectErr != nil || closeErr != nil {
		return errors.Join(projectErr, closeErr)
	}
	return mergeCompatibleManifestFiles(currentManifest, retainedPath, destination)
}

func validateRetainedYUMPayloadPaths(reader io.Reader, legacyRoot string) error {
	prefix := path.Join(legacyRoot, "Packages") + "/"
	stream := views.NewReader(reader)
	for {
		entry, err := stream.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if !strings.HasPrefix(entry.Path, prefix) {
			return fmt.Errorf("retained YUM payload %q escapes %s", entry.Path, prefix)
		}
		relative := strings.TrimPrefix(entry.Path, prefix)
		parts := strings.Split(relative, "/")
		if len(parts) != 2 || len(parts[0]) != 1 || path.Base(parts[1]) != parts[1] || !strings.HasSuffix(parts[1], ".rpm") {
			return fmt.Errorf("retained YUM payload path %q is not canonical", entry.Path)
		}
	}
}

func mergeCompatibleManifestFiles(leftPath, rightPath, destinationPath string) (resultErr error) {
	left, err := os.Open(leftPath)
	if err != nil {
		return err
	}
	right, err := os.Open(rightPath)
	if err != nil {
		_ = left.Close()
		return err
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = left.Close()
		_ = right.Close()
		return err
	}
	committed := false
	defer func() {
		_ = left.Close()
		_ = right.Close()
		_ = destination.Close()
		if !committed {
			_ = os.Remove(destinationPath)
		}
	}()
	writer := bufio.NewWriterSize(destination, 256*1024)
	leftReader, rightReader := manifest.NewReader(left), manifest.NewReader(right)
	leftEntry, leftErr := leftReader.Next()
	rightEntry, rightErr := rightReader.Next()
	for !errors.Is(leftErr, io.EOF) || !errors.Is(rightErr, io.EOF) {
		if leftErr != nil && !errors.Is(leftErr, io.EOF) || rightErr != nil && !errors.Is(rightErr, io.EOF) {
			return errors.Join(leftErr, rightErr)
		}
		var entry manifest.Entry
		switch {
		case errors.Is(leftErr, io.EOF):
			entry = rightEntry
			rightEntry, rightErr = rightReader.Next()
		case errors.Is(rightErr, io.EOF):
			entry = leftEntry
			leftEntry, leftErr = leftReader.Next()
		case leftEntry.Path < rightEntry.Path:
			entry = leftEntry
			leftEntry, leftErr = leftReader.Next()
		case rightEntry.Path < leftEntry.Path:
			entry = rightEntry
			rightEntry, rightErr = rightReader.Next()
		default:
			if leftEntry.Size != rightEntry.Size || leftEntry.SHA256 != rightEntry.SHA256 {
				return fmt.Errorf("retained YUM package path %q changed bytes", leftEntry.Path)
			}
			entry = leftEntry
			leftEntry, leftErr = leftReader.Next()
			rightEntry, rightErr = rightReader.Next()
		}
		if err := manifest.WriteEntry(writer, entry); err != nil {
			return err
		}
	}
	if err := errors.Join(writer.Flush(), destination.Sync(), destination.Close(), left.Close(), right.Close()); err != nil {
		return err
	}
	committed = true
	return nil
}
