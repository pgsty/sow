package yumrepo

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	crpm "github.com/cavaliergopher/rpm"
)

func TestWeakDependenciesRoundTripThroughRPMAndPrimaryXML(t *testing.T) {
	rpmPath := filepath.Join(t.TempDir(), "weak-deps-1.2.3-4.x86_64.rpm")
	writeRPMFixture(t, rpmPath, "weak-deps",
		stringTag(5046, "docker-ce-rootless-extras"), intTag(5048, 0), stringTag(5047, ""),
		stringTag(5049, "suggested-tool"), intTag(5051, (1<<2)|(1<<3)), stringTag(5050, "1:2.0-3"),
		stringTag(5052, "(weak-deps if helper)"), intTag(5054, 0), stringTag(5053, ""),
		stringTag(5055, "docker-ce-cli"), intTag(5057, 1<<3), stringTag(5056, "0:29.6.1-1.el9"),
	)

	dest := filepath.Join(t.TempDir(), "repodata")
	generation, err := GenerateFlatUnsigned(context.Background(), dest, 1, &SliceIterator{Inputs: []PackageInput{{Path: rpmPath}}})
	if err != nil {
		t.Fatalf("GenerateFlatUnsigned: %v", err)
	}
	primary := readArtifact(t, dest, generation.Artifacts[0])
	groups, order, err := primaryDependencyGroups(primary)
	if err != nil {
		t.Fatalf("parse primary XML: %v", err)
	}

	want := map[string][]map[string]string{
		"suggests":    {{"name": "suggested-tool", "flags": "GE", "epoch": "1", "ver": "2.0", "rel": "3"}},
		"enhances":    {{"name": "docker-ce-cli", "flags": "EQ", "epoch": "0", "ver": "29.6.1", "rel": "1.el9"}},
		"recommends":  {{"name": "docker-ce-rootless-extras"}},
		"supplements": {{"name": "(weak-deps if helper)"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("weak dependency groups = %#v, want %#v\n%s", groups, want, primary)
	}
	if wantOrder := []string{"suggests", "enhances", "recommends", "supplements"}; !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("weak dependency XML order = %v, want %v", order, wantOrder)
	}
}

func TestGenerateManagedConcurrentIsWorkerDeterministic(t *testing.T) {
	inputs := make([]PackageInput, 0, 4)
	for _, name := range []string{"alpha", "beta", "delta", "gamma"} {
		basename := name + "-1.2.3-4.x86_64.rpm"
		filename := filepath.Join(t.TempDir(), basename)
		writeRPMFixture(t, filename, name)
		inputs = append(inputs, PackageInput{Path: filename, Basename: basename, Location: "pool/" + name[:1] + "/" + name + "/" + basename})
	}
	left, right := filepath.Join(t.TempDir(), "repodata"), filepath.Join(t.TempDir(), "repodata")
	one, err := GenerateManagedConcurrent(context.Background(), left, 7, &SliceIterator{Inputs: inputs}, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	four, err := GenerateManagedConcurrent(context.Background(), right, 7, &SliceIterator{Inputs: inputs}, nil, 4)
	if err != nil {
		t.Fatal(err)
	}
	if one.Packages != four.Packages || one.Revision != four.Revision || one.RepomdSHA256 != four.RepomdSHA256 || one.IdentitySHA256 != four.IdentitySHA256 || !reflect.DeepEqual(one.Artifacts, four.Artifacts) {
		t.Fatalf("worker count changed generation: one=%#v four=%#v", one, four)
	}
	paths := []string{"repomd.xml"}
	for _, artifact := range one.Artifacts {
		paths = append(paths, filepath.Base(artifact.Path))
	}
	for _, relative := range paths {
		leftBytes, leftErr := os.ReadFile(filepath.Join(left, filepath.FromSlash(relative)))
		rightBytes, rightErr := os.ReadFile(filepath.Join(right, filepath.FromSlash(relative)))
		if leftErr != nil || rightErr != nil || !bytes.Equal(leftBytes, rightBytes) {
			t.Fatalf("worker count changed %s: left=%v right=%v equal=%t", relative, leftErr, rightErr, bytes.Equal(leftBytes, rightBytes))
		}
	}
	if _, err := GenerateManagedConcurrent(context.Background(), filepath.Join(t.TempDir(), "repodata"), 7, &SliceIterator{Inputs: inputs}, nil, 0); err == nil {
		t.Fatal("zero workers accepted")
	}
}

func TestManagedPackageLocationRequiresPortableLowercaseShard(t *testing.T) {
	const basename = "PolarDB-17.9.1.0-1.el10.aarch64.rpm"
	if err := validateManagedPackageLocation("PolarDB", basename, "pool/p/PolarDB/"+basename); err != nil {
		t.Fatalf("portable location rejected: %v", err)
	}
	if err := validateManagedPackageLocation("PolarDB", basename, "pool/P/PolarDB/"+basename); err == nil {
		t.Fatal("case-preserving shard accepted")
	}
}

func TestWeakDependencyTagAlignmentRejected(t *testing.T) {
	rpmPath := filepath.Join(t.TempDir(), "misaligned-1.2.3-4.x86_64.rpm")
	writeRPMFixture(t, rpmPath, "misaligned",
		stringTag(5046, "one", "two"), intTag(5048, 0), stringTag(5047, "", ""),
	)
	_, err := readPackage(context.Background(), PackageInput{Path: rpmPath})
	if err == nil || !strings.Contains(err.Error(), "recommends") || !strings.Contains(err.Error(), "misaligned") {
		t.Fatalf("misaligned weak dependency error = %v", err)
	}
}

func TestLegacyMissingOKRequirementProjectsAsRecommend(t *testing.T) {
	rpmPath := filepath.Join(t.TempDir(), "legacy-weak-1.2.3-4.x86_64.rpm")
	writeRPMFixture(t, rpmPath, "legacy-weak",
		stringTag(tagRequireNames, "legacy-optional", "bash"),
		intTag(tagRequireFlags, 1<<19, (1<<2)|(1<<3)),
		stringTag(tagRequireEVRs, "0:2.0-1", "0:4.0-1"),
	)
	dest := filepath.Join(t.TempDir(), "repodata")
	generation, err := GenerateFlatUnsigned(context.Background(), dest, 1, &SliceIterator{Inputs: []PackageInput{{Path: rpmPath}}})
	if err != nil {
		t.Fatal(err)
	}
	primary := string(readArtifact(t, dest, generation.Artifacts[0]))
	requiresStart, requiresEnd := strings.Index(primary, "<rpm:requires>"), strings.Index(primary, "</rpm:requires>")
	if requiresStart < 0 || requiresEnd < requiresStart || !strings.Contains(primary[requiresStart:requiresEnd], `name="bash"`) || strings.Contains(primary[requiresStart:requiresEnd], `name="legacy-optional"`) {
		t.Fatalf("legacy weak dependency leaked into requires:\n%s", primary)
	}
	recommendsStart, recommendsEnd := strings.Index(primary, "<rpm:recommends>"), strings.Index(primary, "</rpm:recommends>")
	if recommendsStart < 0 || recommendsEnd < recommendsStart || !strings.Contains(primary[recommendsStart:recommendsEnd], `name="legacy-optional" epoch="0" ver="2.0" rel="1"`) {
		t.Fatalf("legacy weak dependency missing from recommends:\n%s", primary)
	}
	catalogPackage, err := InspectCatalogPackage(context.Background(), PackageInput{Path: rpmPath})
	if err != nil {
		t.Fatal(err)
	}
	var catalogRequires []string
	for _, relation := range catalogPackage.Relations {
		if relation.Kind == "requires" {
			catalogRequires = append(catalogRequires, relation.Name)
		}
	}
	if want := []string{"legacy-optional", "bash"}; !reflect.DeepEqual(catalogRequires, want) {
		t.Fatalf("catalog requires = %v, want raw header requires %v", catalogRequires, want)
	}
}

func TestRequiresPreClassificationMatchesRPMMetadataConvention(t *testing.T) {
	names := []string{"posttrans", "prereq", "pretrans", "script-pre", "script-post", "interpreter", "script-preun", "script-postun", "verify", "ordinary"}
	flags := []int64{1 << 5, 1 << 6, 1 << 7, 1 << 9, 1 << 10, 1 << 8, 1 << 11, 1 << 12, 1 << 13, 0}
	header := &crpm.Header{Tags: map[int]*crpm.Tag{
		tagRequireNames: {ID: tagRequireNames, Type: crpm.TagTypeStringArray, Value: names},
		tagRequireFlags: {ID: tagRequireFlags, Type: crpm.TagTypeInt32, Value: flags},
		tagRequireEVRs:  {ID: tagRequireEVRs, Type: crpm.TagTypeStringArray, Value: make([]string, len(names))},
	}}
	dependencies, err := readDependencies(header, tagRequireNames, tagRequireFlags, tagRequireEVRs, true)
	if err != nil {
		t.Fatal(err)
	}
	for i, dependency := range dependencies {
		want := i < 5
		if dependency.Pre != want {
			t.Errorf("dependency %q pre=%t, want %t", dependency.Name, dependency.Pre, want)
		}
	}
}

func TestFilelistsDirectoryTakesPrecedenceOverGhostFlag(t *testing.T) {
	metadata := &packageMetadata{
		Name: "filesystem", Version: "1", Release: "1", Arch: "noarch", Checksum: strings.Repeat("a", 64),
		Files: []rpmFile{
			{Name: "/var/lib/example", Mode: 0040000, Flags: 1 << 6},
			{Name: "/var/lib/example/ghost", Mode: 0100000, Flags: 1 << 6},
		},
	}
	var output bytes.Buffer
	if err := writeFilelistsPackage(&output, metadata); err != nil {
		t.Fatal(err)
	}
	want := `<file type="dir">/var/lib/example</file>`
	if !strings.Contains(output.String(), want) {
		t.Fatalf("directory carrying ghost flag was not rendered as dir:\n%s", output.String())
	}
	if !strings.Contains(output.String(), `<file type="ghost">/var/lib/example/ghost</file>`) {
		t.Fatalf("regular ghost file lost ghost type:\n%s", output.String())
	}
}

func TestNormalizeRPMRequiresMatchesRepositoryProjection(t *testing.T) {
	provided := []dependency{{Name: "self", Flags: "EQ", Epoch: "0", Version: "1", Release: "1"}}
	requires := []dependency{
		{Name: "rpmlib(PayloadIsZstd)", Flags: "LE", Epoch: "0", Version: "5.4.18", Release: "1"},
		{Name: "/etc/fixture.conf"},
		{Name: "/usr/share/doc/fixture.txt"},
		{Name: "self", Flags: "EQ", Epoch: "0", Version: "1", Release: "1"},
		{Name: "bash", Pre: true},
		{Name: "bash", Pre: true},
		{Name: "bash"},
		{Name: "libc.so.6()(64bit)"},
		{Name: "libc.so.6(GLIBC_2.17)(64bit)"},
		{Name: "libc.so.6(GLIBC_2.34)(64bit)"},
	}
	files := []rpmFile{{Name: "/etc/fixture.conf"}, {Name: "/usr/share/doc/fixture.txt"}}
	got := normalizeRPMRequires(requires, provided, files)
	want := []dependency{
		{Name: "/usr/share/doc/fixture.txt"},
		{Name: "bash", Pre: true},
		{Name: "bash"},
		{Name: "libc.so.6(GLIBC_2.34)(64bit)"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized requires = %#v, want %#v", got, want)
	}
}

func TestPrimaryPackageListsOnlyYUMPrimaryFiles(t *testing.T) {
	metadata := &packageMetadata{
		Name: "fixture", Version: "1", Release: "1", Arch: "noarch", Checksum: strings.Repeat("a", 64),
		Files: []rpmFile{
			{Name: "/etc/fixture.conf", Mode: 0100000},
			{Name: "/usr/bin/fixture", Mode: 0100000},
			{Name: "/usr/share/locale/bin/LC_MESSAGES", Mode: 0100000},
			{Name: "/usr/lib/sendmail", Mode: 0100000},
			{Name: "/usr/share/doc/fixture.txt", Mode: 0100000},
			{Name: "/etc/fixture.d", Mode: 0040000},
		},
	}
	var output bytes.Buffer
	if err := writePrimaryPackage(&output, metadata); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{"/etc/fixture.conf", "/usr/bin/fixture", "/usr/share/locale/bin/LC_MESSAGES", "/usr/lib/sendmail", "/etc/fixture.d"} {
		if !strings.Contains(output.String(), ">"+wanted+"</file>") {
			t.Errorf("primary XML missing %q:\n%s", wanted, output.String())
		}
	}
	if !strings.Contains(output.String(), `<file type="dir">/etc/fixture.d</file>`) {
		t.Errorf("primary XML lost primary directory type:\n%s", output.String())
	}
	for _, forbidden := range []string{"/usr/share/doc/fixture.txt"} {
		if strings.Contains(output.String(), forbidden) {
			t.Errorf("primary XML contains non-primary path %q:\n%s", forbidden, output.String())
		}
	}
}

func primaryDependencyGroups(document []byte) (map[string][]map[string]string, []string, error) {
	wanted := map[string]struct{}{"suggests": {}, "enhances": {}, "recommends": {}, "supplements": {}}
	groups := make(map[string][]map[string]string, len(wanted))
	var order []string
	var current string
	decoder := xml.NewDecoder(bytes.NewReader(document))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		switch value := token.(type) {
		case xml.StartElement:
			if value.Name.Space != rpmNS {
				continue
			}
			if _, ok := wanted[value.Name.Local]; ok {
				current = value.Name.Local
				order = append(order, current)
				continue
			}
			if value.Name.Local == "entry" && current != "" {
				attrs := make(map[string]string, len(value.Attr))
				for _, attr := range value.Attr {
					attrs[attr.Name.Local] = attr.Value
				}
				groups[current] = append(groups[current], attrs)
			}
		case xml.EndElement:
			if value.Name.Space == rpmNS && value.Name.Local == current {
				current = ""
			}
		}
	}
	for group := range wanted {
		if _, ok := groups[group]; !ok {
			return nil, nil, fmt.Errorf("missing rpm:%s", group)
		}
	}
	return groups, order, nil
}
