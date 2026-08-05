package yumrepo

import (
	"context"
	"fmt"
	"strconv"
)

// CatalogRelation is one RPM header relationship projected into SOW's
// disposable query cache.
type CatalogRelation struct {
	Kind     string
	Group    int
	Name     string
	Operator string
	Version  string
	Pre      bool
}

// CatalogPackage contains the package identity, source RPM and all relationship
// kinds required to rebuild the SQLite query layer from immutable CAS bytes.
type CatalogPackage struct {
	PackageInfo
	DisplayVersion string
	Source         string
	Relations      []CatalogRelation
}

// InspectCatalogPackage uses the same parser and descriptor-hardening path as
// repository generation while exposing source/provides/requires metadata to the
// derived catalog builder.
func InspectCatalogPackage(ctx context.Context, in PackageInput) (CatalogPackage, error) {
	metadata, err := readPackage(ctx, in)
	if err != nil {
		return CatalogPackage{}, err
	}
	result := CatalogPackage{
		PackageInfo: PackageInfo{
			Name: metadata.Name, Version: metadata.Version, Release: metadata.Release,
			Epoch: metadata.Epoch, Arch: metadata.Arch, SHA256: metadata.Checksum,
			Size: metadata.PackageSize, Location: metadata.Location,
		},
		DisplayVersion: rpmDisplayVersion(metadata.Epoch, metadata.Version, metadata.Release),
		Source:         metadata.SourceRPM,
	}
	for _, group := range []struct {
		kind string
		deps []dependency
	}{
		{"provides", metadata.Provides},
		{"requires", metadata.CatalogRequires},
		{"conflicts", metadata.Conflicts},
		{"obsoletes", metadata.Obsoletes},
	} {
		for index, relation := range group.deps {
			result.Relations = append(result.Relations, CatalogRelation{
				Kind: group.kind, Group: index, Name: relation.Name,
				Operator: catalogDependencyOperator(relation.Flags),
				Version:  rpmRelationVersion(relation), Pre: relation.Pre,
			})
		}
	}
	return result, nil
}

func rpmDisplayVersion(epoch int64, version, release string) string {
	value := version
	if release != "" {
		value += "-" + release
	}
	if epoch > 0 {
		value = strconv.FormatInt(epoch, 10) + ":" + value
	}
	return value
}

func rpmRelationVersion(relation dependency) string {
	if relation.Version == "" {
		return ""
	}
	epoch := relation.Epoch
	if epoch == "" {
		epoch = "0"
	}
	value := fmt.Sprintf("%s:%s", epoch, relation.Version)
	if relation.Release != "" {
		value += "-" + relation.Release
	}
	return value
}

func catalogDependencyOperator(value string) string {
	switch value {
	case "LE":
		return "<="
	case "LT":
		return "<"
	case "GE":
		return ">="
	case "GT":
		return ">"
	case "EQ":
		return "="
	default:
		return ""
	}
}
