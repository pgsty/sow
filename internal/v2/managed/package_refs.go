package managed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/pgsty/sow/internal/v2/state"
)

var errPackageReferenceNotFound = errors.New("package reference not found")

func resolvePackageReference(ctx context.Context, store *state.Store, reference string, distNames []string, nameWide bool) ([]state.PackageObject, error) {
	if reference == "" || strings.TrimSpace(reference) != reference || strings.ContainsAny(reference, "\x00\r\n\t") {
		return nil, fmt.Errorf("%w: invalid package reference", ErrRejected)
	}
	objects, err := store.ListPackageObjects(ctx, distNames, false)
	if err != nil {
		return nil, err
	}
	matches := []state.PackageObject{}
	switch {
	case strings.HasPrefix(reference, "sha256:"):
		digest := strings.TrimPrefix(reference, "sha256:")
		if !lowercaseSHA256.MatchString(digest) {
			return nil, fmt.Errorf("%w: sha256 reference requires 64 lowercase hexadecimal digits", ErrRejected)
		}
		for _, object := range objects {
			if object.SHA256 == digest {
				matches = append(matches, object)
			}
		}
	case strings.HasPrefix(reference, "rpm:") || strings.HasPrefix(reference, "deb:"):
		format, coordinate, _ := strings.Cut(reference, ":")
		if coordinate == "" {
			return nil, fmt.Errorf("%w: empty package coordinate", ErrRejected)
		}
		for _, object := range objects {
			if object.Format == format && object.Coordinate == coordinate {
				matches = append(matches, object)
			}
		}
	default:
		for _, object := range objects {
			if object.Filename == reference || object.Name == reference {
				matches = append(matches, object)
			}
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("%w: %w: package reference %q matches no Desired Membership", ErrRejected, errPackageReferenceNotFound, reference)
	}
	bareName := !strings.Contains(reference, ":") && !strings.HasSuffix(reference, ".rpm") && !strings.HasSuffix(reference, ".deb")
	if len(matches) > 1 && !(nameWide && bareName) {
		candidates := make([]string, 0, len(matches))
		for _, object := range matches {
			candidates = append(candidates, object.Format+":"+object.Coordinate+" sha256:"+object.SHA256)
		}
		sort.Strings(candidates)
		return nil, fmt.Errorf("%w: package reference %q is ambiguous: %s", ErrRejected, reference, strings.Join(candidates, ", "))
	}
	return matches, nil
}

func resolvePackageReferences(ctx context.Context, store *state.Store, references, distNames []string, nameWide bool) ([]state.PackageObject, error) {
	byDigest := map[string]state.PackageObject{}
	for _, reference := range references {
		matches, err := resolvePackageReference(ctx, store, reference, distNames, nameWide)
		if err != nil {
			return nil, err
		}
		for _, object := range matches {
			byDigest[object.SHA256] = object
		}
	}
	result := make([]state.PackageObject, 0, len(byDigest))
	for _, object := range byDigest {
		result = append(result, object)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Format != result[j].Format {
			return result[i].Format < result[j].Format
		}
		if result[i].Coordinate != result[j].Coordinate {
			return result[i].Coordinate < result[j].Coordinate
		}
		return result[i].SHA256 < result[j].SHA256
	})
	if len(result) == 0 {
		return nil, errors.New("managed: no package references resolved")
	}
	return result, nil
}
