package geodata

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Paths supplies instance-local defaults for the geosite:, geoip: and asn:
// shortcuts. Empty fields retain the conventional working-directory defaults.
// Explicit ext: expressions always select their own file.
type Paths struct {
	GeoSite string `yaml:"geosite"`
	GeoIP   string `yaml:"geoip"`
	ASN     string `yaml:"asn"`
}

// Absolute fixes configured relative paths to the current working directory.
// Files are opened lazily by their consumers, so unused defaults need not exist.
func (p Paths) Absolute() (Paths, error) {
	for _, field := range []struct {
		name string
		path *string
	}{{"geosite", &p.GeoSite}, {"geoip", &p.GeoIP}, {"asn", &p.ASN}} {
		if *field.path == "" {
			continue
		}
		path, err := filepath.Abs(*field.path)
		if err != nil {
			return Paths{}, fmt.Errorf("geodata %s path: %w", field.name, err)
		}
		*field.path = path
	}
	return p, nil
}

// ParseDomainExp applies only the instance's GeoSite shortcut default. Parsing
// and explicit file syntax remain compatible with the package-level parser.
func (p Paths) ParseDomainExp(s string) (file, code string, attrs []string, ok bool, err error) {
	file, code, attrs, ok, err = ParseDomainExp(s)
	if err == nil && ok && p.GeoSite != "" && strings.HasPrefix(s, "geosite:") {
		file = p.GeoSite
	}
	return
}

// ParseIPExp applies the instance's GeoIP or ASN default to shortcut expressions.
func (p Paths) ParseIPExp(s string) (file string, kind IPExpKind, code string, ok bool, err error) {
	file, kind, code, ok, err = ParseIPExp(s)
	if err == nil && ok && file == "" {
		if kind == IPExpASN {
			file = p.ASN
		} else {
			file = p.GeoIP
		}
	}
	return
}
