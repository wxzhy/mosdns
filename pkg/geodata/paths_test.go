package geodata

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathsAbsolute(t *testing.T) {
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	absolute := Paths{
		GeoSite: filepath.Join(cwd, "sites", "geosite.dat"),
		GeoIP:   filepath.Join(cwd, "countries", "Country.mmdb"),
		ASN:     filepath.Join(cwd, "networks", "ASN.mmdb"),
	}
	for _, tc := range []struct {
		name string
		in   Paths
		want Paths
	}{
		{name: "empty"},
		{
			name: "relative",
			in: Paths{
				GeoSite: filepath.Join("sites", "geosite.dat"),
				GeoIP:   filepath.Join("countries", "Country.mmdb"),
				ASN:     filepath.Join("networks", "ASN.mmdb"),
			},
			want: absolute,
		},
		{name: "absolute", in: absolute, want: absolute},
		{
			name: "mixed",
			in:   Paths{GeoSite: filepath.Join("sites", "geosite.dat"), ASN: absolute.ASN},
			want: Paths{GeoSite: absolute.GeoSite, ASN: absolute.ASN},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.in
			// Resolving defaults must not require the database files to exist.
			got, err := tc.in.Absolute()
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("Absolute() = %+v, want %+v", got, tc.want)
			}
			if tc.in != original {
				t.Errorf("Absolute() changed input to %+v, want %+v", tc.in, original)
			}
		})
	}
}

func TestPathsAbsoluteSurvivesWorkingDirectoryChange(t *testing.T) {
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative := Paths{GeoSite: "geosite.dat", GeoIP: "Country.mmdb", ASN: "ASN.mmdb"}
	fixed, err := relative.Absolute()
	if err != nil {
		t.Fatal(err)
	}
	want := Paths{
		GeoSite: filepath.Join(cwd, "geosite.dat"),
		GeoIP:   filepath.Join(cwd, "Country.mmdb"),
		ASN:     filepath.Join(cwd, "ASN.mmdb"),
	}

	t.Chdir(t.TempDir())
	resolvedAgain, err := fixed.Absolute()
	if err != nil {
		t.Fatal(err)
	}
	if fixed != want || resolvedAgain != want {
		t.Fatalf("fixed paths changed with cwd: fixed = %+v, resolved again = %+v, want %+v", fixed, resolvedAgain, want)
	}
	other, err := relative.Absolute()
	if err != nil {
		t.Fatal(err)
	}
	if other.GeoSite == fixed.GeoSite || other.GeoIP == fixed.GeoIP || other.ASN == fixed.ASN {
		t.Fatalf("relative paths did not follow the new cwd: got %+v, previous %+v", other, fixed)
	}
}
