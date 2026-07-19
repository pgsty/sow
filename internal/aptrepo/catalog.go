package aptrepo

import (
	"fmt"

	"pault.ag/go/debian/dependency"
)

// CatalogRelation is the lossless package-level relationship projection used
// by SOW's disposable SQLite cache. Group numbers model comma-separated AND
// relations and Alternative numbers preserve the order of pipe-separated OR
// possibilities.
type CatalogRelation struct {
	Kind          string
	Group         int
	Alternative   int
	Name          string
	Operator      string
	Version       string
	ArchQualifier string
	ArchFilterNot bool
	Architectures []string
}

// CatalogRelations returns dependency and provider metadata from the exact
// control paragraph retained by InspectPackage. It never reparses generated
// Packages output and therefore preserves the package body's own metadata.
func (p Package) CatalogRelations() ([]CatalogRelation, error) {
	fields := []struct {
		kind string
		name string
	}{
		{"pre-depends", "Pre-Depends"},
		{"depends", "Depends"},
		{"recommends", "Recommends"},
		{"suggests", "Suggests"},
		{"enhances", "Enhances"},
		{"breaks", "Breaks"},
		{"conflicts", "Conflicts"},
		{"replaces", "Replaces"},
		{"provides", "Provides"},
		{"built-using", "Built-Using"},
	}
	var result []CatalogRelation
	for _, field := range fields {
		raw := p.paragraph.Values[field.name]
		if raw == "" {
			continue
		}
		parsed, err := dependency.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("aptrepo: parse %s for %s: %w", field.name, p.Name, err)
		}
		for group, relation := range parsed.Relations {
			for alternative, possibility := range relation.Possibilities {
				projected := CatalogRelation{
					Kind: field.kind, Group: group, Alternative: alternative,
					Name: possibility.Name,
				}
				if possibility.Version != nil {
					projected.Operator = possibility.Version.Operator
					projected.Version = possibility.Version.Number
				}
				if possibility.Arch != nil {
					projected.ArchQualifier = possibility.Arch.String()
				}
				if possibility.Architectures != nil {
					projected.ArchFilterNot = possibility.Architectures.Not
					for _, architecture := range possibility.Architectures.Architectures {
						projected.Architectures = append(projected.Architectures, architecture.String())
					}
				}
				result = append(result, projected)
			}
		}
	}
	return result, nil
}
