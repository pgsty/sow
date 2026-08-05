package yumrepo

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	commonNS    = "http://linux.duke.edu/metadata/common"
	rpmNS       = "http://linux.duke.edu/metadata/rpm"
	filelistsNS = "http://linux.duke.edu/metadata/filelists"
	otherNS     = "http://linux.duke.edu/metadata/other"
	repoNS      = "http://linux.duke.edu/metadata/repo"
)

type xmlBodies struct {
	primary   *bufio.Writer
	filelists *bufio.Writer
	other     *bufio.Writer
}

func (b *xmlBodies) writePackage(m *packageMetadata) error {
	if err := writePrimaryPackage(b.primary, m); err != nil {
		return err
	}
	if err := writeFilelistsPackage(b.filelists, m); err != nil {
		return err
	}
	return writeOtherPackage(b.other, m)
}

func writePrimaryPackage(w io.Writer, m *packageMetadata) error {
	if _, err := io.WriteString(w, "<package type=\"rpm\">\n"); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{
		{"name", m.Name}, {"arch", m.Arch},
	} {
		if err := element(w, "  ", field.name, field.value); err != nil {
			return err
		}
	}
	if err := emptyElement(w, "  ", "version", [][2]string{{"epoch", fmt.Sprint(m.Epoch)}, {"ver", m.Version}, {"rel", m.Release}}); err != nil {
		return err
	}
	if err := textElementAttrs(w, "  ", "checksum", m.Checksum, [][2]string{{"type", "sha256"}, {"pkgid", "YES"}}); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{
		{"summary", m.Summary}, {"description", m.Description}, {"packager", m.Packager}, {"url", m.URL},
	} {
		if err := element(w, "  ", field.name, field.value); err != nil {
			return err
		}
	}
	if err := emptyElement(w, "  ", "time", [][2]string{{"file", fmt.Sprint(m.FileTime)}, {"build", fmt.Sprint(m.BuildTime)}}); err != nil {
		return err
	}
	if err := emptyElement(w, "  ", "size", [][2]string{{"package", fmt.Sprint(m.PackageSize)}, {"installed", fmt.Sprint(m.InstalledSize)}, {"archive", fmt.Sprint(m.ArchiveSize)}}); err != nil {
		return err
	}
	if err := emptyElement(w, "  ", "location", [][2]string{{"href", m.Location}}); err != nil {
		return err
	}
	if _, err := io.WriteString(w, "  <format>\n"); err != nil {
		return err
	}
	for _, field := range []struct{ name, value string }{
		{"rpm:license", m.License}, {"rpm:vendor", m.Vendor}, {"rpm:group", m.Group},
		{"rpm:buildhost", m.BuildHost}, {"rpm:sourcerpm", m.SourceRPM},
	} {
		if err := element(w, "    ", field.name, field.value); err != nil {
			return err
		}
	}
	if err := emptyElement(w, "    ", "rpm:header-range", [][2]string{{"start", fmt.Sprint(m.HeaderStart)}, {"end", fmt.Sprint(m.HeaderEnd)}}); err != nil {
		return err
	}
	for _, group := range []struct {
		name string
		deps []dependency
	}{
		{"rpm:provides", m.Provides}, {"rpm:requires", m.Requires}, {"rpm:conflicts", m.Conflicts}, {"rpm:obsoletes", m.Obsoletes},
		{"rpm:suggests", m.Suggests}, {"rpm:enhances", m.Enhances}, {"rpm:recommends", m.Recommends}, {"rpm:supplements", m.Supplements},
	} {
		if len(group.deps) == 0 {
			continue
		}
		if _, err := fmt.Fprintf(w, "    <%s>\n", group.name); err != nil {
			return err
		}
		for _, dep := range group.deps {
			attrs := [][2]string{{"name", dep.Name}}
			if dep.Flags != "" {
				attrs = append(attrs, [2]string{"flags", dep.Flags})
			}
			if dep.Version != "" {
				attrs = append(attrs, [2]string{"epoch", dep.Epoch}, [2]string{"ver", dep.Version})
				if dep.Release != "" {
					attrs = append(attrs, [2]string{"rel", dep.Release})
				}
			}
			if dep.Pre {
				attrs = append(attrs, [2]string{"pre", "1"})
			}
			if err := emptyElement(w, "      ", "rpm:entry", attrs); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "    </%s>\n", group.name); err != nil {
			return err
		}
	}
	for _, f := range m.Files {
		if !isPrimaryRPMFile(f.Name) {
			continue
		}
		attrs := [][2]string(nil)
		switch {
		case f.Mode&0170000 == 0040000:
			attrs = [][2]string{{"type", "dir"}}
		case f.Flags&(1<<6) != 0:
			attrs = [][2]string{{"type", "ghost"}}
		}
		if err := textElementAttrs(w, "    ", "file", f.Name, attrs); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "  </format>\n</package>\n")
	return err
}

func writeFilelistsPackage(w io.Writer, m *packageMetadata) error {
	if _, err := io.WriteString(w, "<package"); err != nil {
		return err
	}
	if err := writeAttrs(w, [][2]string{{"pkgid", m.Checksum}, {"name", m.Name}, {"arch", m.Arch}}); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ">\n"); err != nil {
		return err
	}
	if err := emptyElement(w, "  ", "version", [][2]string{{"epoch", fmt.Sprint(m.Epoch)}, {"ver", m.Version}, {"rel", m.Release}}); err != nil {
		return err
	}
	for _, f := range m.Files {
		attrs := [][2]string(nil)
		switch {
		case f.Mode&0170000 == 0040000:
			attrs = [][2]string{{"type", "dir"}}
		case f.Flags&(1<<6) != 0:
			attrs = [][2]string{{"type", "ghost"}}
		}
		if err := textElementAttrs(w, "  ", "file", f.Name, attrs); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "</package>\n")
	return err
}

func writeOtherPackage(w io.Writer, m *packageMetadata) error {
	if _, err := io.WriteString(w, "<package"); err != nil {
		return err
	}
	if err := writeAttrs(w, [][2]string{{"pkgid", m.Checksum}, {"name", m.Name}, {"arch", m.Arch}}); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ">\n"); err != nil {
		return err
	}
	if err := emptyElement(w, "  ", "version", [][2]string{{"epoch", fmt.Sprint(m.Epoch)}, {"ver", m.Version}, {"rel", m.Release}}); err != nil {
		return err
	}
	for _, c := range m.Changelogs {
		if err := textElementAttrs(w, "  ", "changelog", c.Text, [][2]string{{"author", c.Author}, {"date", fmt.Sprint(c.Date)}}); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "</package>\n")
	return err
}

func element(w io.Writer, indent, name, text string) error {
	return textElementAttrs(w, indent, name, text, nil)
}

func textElementAttrs(w io.Writer, indent, name, text string, attrs [][2]string) error {
	if _, err := io.WriteString(w, indent+"<"+name); err != nil {
		return err
	}
	if err := writeAttrs(w, attrs); err != nil {
		return err
	}
	if _, err := io.WriteString(w, ">"); err != nil {
		return err
	}
	if err := escapeXML(w, text); err != nil {
		return err
	}
	_, err := io.WriteString(w, "</"+name+">\n")
	return err
}

func emptyElement(w io.Writer, indent, name string, attrs [][2]string) error {
	if _, err := io.WriteString(w, indent+"<"+name); err != nil {
		return err
	}
	if err := writeAttrs(w, attrs); err != nil {
		return err
	}
	_, err := io.WriteString(w, "/>\n")
	return err
}

func writeAttrs(w io.Writer, attrs [][2]string) error {
	for _, attr := range attrs {
		if _, err := io.WriteString(w, " "+attr[0]+"=\""); err != nil {
			return err
		}
		if err := escapeXML(w, attr[1]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\""); err != nil {
			return err
		}
	}
	return nil
}

func escapeXML(w io.Writer, value string) error {
	value = cleanXMLString(value)
	return xml.EscapeText(w, []byte(value))
}

func cleanXMLString(value string) string {
	if validXMLString(value) {
		return value
	}
	var b strings.Builder
	b.Grow(len(value))
	for len(value) > 0 {
		r, n := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && n == 1 {
			b.WriteRune(utf8.RuneError)
			value = value[1:]
			continue
		}
		if validXMLRune(r) {
			b.WriteRune(r)
		} else {
			b.WriteRune(utf8.RuneError)
		}
		value = value[n:]
	}
	return b.String()
}

func validXMLString(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if !validXMLRune(r) {
			return false
		}
	}
	return true
}

func validXMLRune(r rune) bool {
	return r == '\t' || r == '\n' || r == '\r' ||
		(r >= 0x20 && r <= 0xD7FF) || (r >= 0xE000 && r <= 0xFFFD) ||
		(r >= 0x10000 && r <= 0x10FFFF)
}
