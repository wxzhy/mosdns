package coremain

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestLowPrivilegeServiceConfig(t *testing.T) {
	windows, err := newLowPrivilegeServiceConfig("windows-service", `C:\mosdns\mosdns.exe`, `C:\mosdns`, `C:\mosdns\config.yaml`)
	if err != nil {
		t.Fatal(err)
	}
	if windows.UserName != `NT AUTHORITY\LocalService` {
		t.Fatalf("Windows account = %q, want LocalService", windows.UserName)
	}
	wantArguments := []string{"start", "--as-service", "-d", `C:\mosdns`, "-c", `C:\mosdns\config.yaml`}
	if !reflect.DeepEqual(windows.Arguments, wantArguments) {
		t.Errorf("Windows arguments = %q, want %q", windows.Arguments, wantArguments)
	}
	if _, ok := windows.Option["SystemdScript"]; ok {
		t.Error("Windows configuration contains a systemd unit")
	}

	first, err := newLowPrivilegeServiceConfig("linux-systemd", "/usr/local/bin/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	second, err := newLowPrivilegeServiceConfig("linux-systemd", "/usr/local/bin/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if first.UserName != "mosdns" || first.WorkingDirectory != "/opt/mosdns" {
		t.Errorf("Linux identity/directory = %q/%q", first.UserName, first.WorkingDirectory)
	}
	unit, ok := second.Option["SystemdScript"].(string)
	if !ok || unit == "" {
		t.Fatal("Linux service is missing its systemd unit")
	}
	first.Option["SystemdScript"] = "changed"
	if len(first.Arguments) > 0 {
		first.Arguments[0] = "changed"
		if reflect.DeepEqual(first.Arguments, second.Arguments) {
			t.Error("service configurations share their argument slice")
		}
	}
	if second.Option["SystemdScript"] != unit {
		t.Error("service configurations share their option map")
	}
	if windows.UserName != `NT AUTHORITY\LocalService` || !reflect.DeepEqual(windows.Arguments, wantArguments) {
		t.Error("building Linux configurations mutated the Windows configuration")
	}
	for _, platform := range []string{"", "linux-procd", "linux-sysv", "darwin-launchd"} {
		if _, err := newLowPrivilegeServiceConfig(platform, "/usr/local/bin/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml"); err == nil {
			t.Errorf("unsupported platform %q was accepted", platform)
		}
	}
}

func TestServiceIdentityGuard(t *testing.T) {
	for _, tc := range []struct {
		name, platform string
		uid, gid       int
		wantError      bool
	}{
		{"root user", "linux-systemd", 0, 65534, true},
		{"root group", "linux-systemd", 65534, 0, true},
		{"root user and group", "linux-systemd", 0, 0, true},
		{"unknown user", "linux-systemd", -1, 65534, true},
		{"unknown group", "linux-systemd", 65534, -1, true},
		{"unknown user and group", "linux-systemd", -1, -1, true},
		{"dynamic account", "linux-systemd", 61184, 61184, false},
		{"static account", "linux-systemd", 999, 998, false},
		{"Windows has no POSIX IDs", "windows-service", -1, -1, false},
		{"Windows IDs are not Linux credentials", "windows-service", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateServiceIdentity(tc.platform, tc.uid, tc.gid)
			if (err != nil) != tc.wantError {
				t.Errorf("identity guard for %s uid=%d gid=%d: %v; want error=%v", tc.platform, tc.uid, tc.gid, err, tc.wantError)
			}
		})
	}
}

func TestSystemdServiceUsesCredentialWithoutChangingWorkingDirectory(t *testing.T) {
	for _, extension := range []string{".yaml", ".yml", ".json", ".toml"} {
		t.Run(extension, func(t *testing.T) {
			config := "/home/operator/private/settings" + extension
			unit, err := renderSystemdService("/usr/local/bin/mosdns", "/opt/mosdns", config)
			if err != nil {
				t.Fatal(err)
			}
			for _, directive := range []string{
				"User=mosdns",
				"AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW",
				"CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW",
			} {
				if !strings.Contains(unit, directive+"\n") {
					t.Errorf("unit is missing %q", directive)
				}
			}
			for _, name := range []string{"DynamicUser", "NoNewPrivileges"} {
				if got := serviceUnitDirective(t, unit, name); got != "yes" && got != "true" {
					t.Errorf("%s = %q, want enabled", name, got)
				}
			}
			credential := "config" + extension
			if got := serviceUnitScalar(t, unit, "LoadCredential"); got != credential+":"+config {
				t.Errorf("LoadCredential = %q", got)
			}
			if got := serviceUnitScalar(t, unit, "WorkingDirectory"); got != "/opt/mosdns" {
				t.Errorf("WorkingDirectory = %q", got)
			}
			execStart := serviceUnitDirective(t, unit, "ExecStart")
			want := []string{"/usr/local/bin/mosdns", "mosdns", "start", "--as-service", "-d", "/opt/mosdns", "-c", "${CREDENTIALS_DIRECTORY}/" + credential}
			if got := serviceExecWords(t, execStart); !reflect.DeepEqual(got, want) {
				t.Errorf("ExecStart arguments = %q, want %q", got, want)
			}
			if !strings.Contains(execStart, `"${CREDENTIALS_DIRECTORY}/`+credential+`"`) || strings.Contains(execStart, "$${CREDENTIALS_DIRECTORY}") || strings.Contains(execStart, "%d/") {
				t.Errorf("ExecStart must use the v247 credential environment variable: %q", execStart)
			}
			if strings.Contains(execStart, config) {
				t.Error("ExecStart reads the private source instead of its credential copy")
			}
		})
	}
}

func TestSystemdServiceEscapesLiteralPaths(t *testing.T) {
	executable := `/opt/100%n ${HOME}/mos"dns\{{binary}}`
	workingDir := `/opt/work %n $HOME "quoted"\{data}`
	configPath := `/home/operator/private %n $HOME "quoted"\{config}.yaml`
	unit, err := renderSystemdService(executable, workingDir, configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(unit, "{{") || strings.Contains(unit, "}}") {
		t.Fatal("rendered paths would be interpreted by the service library's template engine")
	}
	execStart := serviceUnitDirective(t, unit, "ExecStart")
	if !strings.HasPrefix(execStart, "@") || !strings.Contains(execStart, "%%n") {
		t.Errorf("ExecStart must set argv[0] explicitly and escape literal specifiers: %q", execStart)
	}
	if !strings.Contains(execStart, "$$HOME") {
		t.Errorf("ExecStart leaves the working directory's dollar sign subject to expansion: %q", execStart)
	}
	want := []string{executable, "mosdns", "start", "--as-service", "-d", workingDir, "-c", "${CREDENTIALS_DIRECTORY}/config.yaml"}
	if got := serviceExecWords(t, execStart); !reflect.DeepEqual(got, want) {
		t.Errorf("special-character arguments = %q, want %q", got, want)
	}
	if got := serviceUnitScalar(t, unit, "WorkingDirectory"); got != workingDir {
		t.Errorf("special-character WorkingDirectory = %q", got)
	}
	if got := serviceUnitScalar(t, unit, "LoadCredential"); got != "config.yaml:"+configPath {
		t.Errorf("special-character LoadCredential = %q", got)
	}
}

func TestSystemdServiceRejectsUnsafePaths(t *testing.T) {
	for _, paths := range [][3]string{
		{"mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml"},
		{"/usr/local/bin/mosdns", "mosdns", "/etc/mosdns/config.yaml"},
		{"/usr/local/bin/mosdns", "/opt/mosdns", "config.yaml"},
		{"/root/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml"},
		{"/home/operator/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml"},
		{"/usr/local/bin/mosdns", "/run/user/1000/mosdns", "/etc/mosdns/config.yaml"},
		{"/usr/local/bin/mosdns", "/opt/../home/operator/mosdns", "/etc/mosdns/config.yaml"},
	} {
		if _, err := renderSystemdService(paths[0], paths[1], paths[2]); err == nil {
			t.Errorf("unsafe paths were accepted: %q", paths)
		}
	}
	for _, control := range []string{"\x00", "\n", "\r", "\t", "\x1b", "\x7f"} {
		for field := range 3 {
			paths := [3]string{"/usr/local/bin/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml"}
			paths[field] += control
			if _, err := renderSystemdService(paths[0], paths[1], paths[2]); err == nil {
				t.Errorf("control %q in field %d was accepted", control, field)
			}
		}
	}
	for _, suffix := range []string{" ", `\`, "{{nested}}"} {
		for _, field := range []int{1, 2} {
			paths := [3]string{"/usr/local/bin/mosdns", "/opt/mosdns", "/etc/mosdns/config.yaml"}
			paths[field] += suffix
			if _, err := renderSystemdService(paths[0], paths[1], paths[2]); err == nil {
				t.Errorf("ambiguous scalar suffix %q in field %d was accepted", suffix, field)
			}
		}
	}
	// The protected-directory policy matches path components, not word prefixes.
	if _, err := renderSystemdService("/rootfs/bin/mosdns", "/homebrew/mosdns", "/etc/mosdns/config.yaml"); err != nil {
		t.Errorf("unrelated path prefixes were rejected: %v", err)
	}
}

func TestSystemdVersionGate(t *testing.T) {
	for _, output := range []string{"systemd 247\n+PAM +AUDIT\n", "systemd 255 (255.4-1ubuntu8)\n", "systemd 262"} {
		if err := validateSystemdVersion(output); err != nil {
			t.Errorf("supported version %q: %v", output, err)
		}
	}
	for _, output := range []string{"", "systemd 246", "systemd 0", "systemd unknown", "systemd 247invalid", "other 255", "warning\nsystemd 255", "systemd 999999999999999999999999999999"} {
		if err := validateSystemdVersion(output); err == nil {
			t.Errorf("invalid or unsupported version %q was accepted", output)
		}
	}
}

func TestResolveServicePaths(t *testing.T) {
	root := t.TempDir()
	executable := writeServiceConfigFixture(t, filepath.Join(root, "bin", "mosdns"), "placeholder binary")
	defaultConfig := writeServiceConfigFixture(t, filepath.Join(root, "bin", "config.yaml"), "plugins: []\n")
	wd, configPath, err := resolveServicePaths(executable, "", "")
	if err != nil || wd != filepath.Dir(executable) || configPath != defaultConfig {
		t.Fatalf("default paths = %q, %q, %v", wd, configPath, err)
	}

	t.Chdir(root)
	// Resolving paths parses configuration, without initializing its plugins.
	configured := writeServiceConfigFixture(t, filepath.Join(root, "work", "private.yaml"), "plugins:\n  - tag: unused\n    type: not-a-registered-plugin\n")
	wd, configPath, err = resolveServicePaths(executable, filepath.Join("work", "."), "private.yaml")
	if err != nil || wd != filepath.Join(root, "work") || configPath != configured {
		t.Fatalf("relative paths = %q, %q, %v", wd, configPath, err)
	}
	wd, configPath, err = resolveServicePaths(executable, filepath.Join(root, "work"), defaultConfig)
	if err != nil || wd != filepath.Join(root, "work") || configPath != defaultConfig {
		t.Fatalf("absolute configuration override = %q, %q, %v", wd, configPath, err)
	}
}

func TestResolveServicePathsFindsConfigFormats(t *testing.T) {
	for _, tc := range []struct{ extension, contents string }{
		{".yaml", "plugins: []\n"},
		{".yml", "plugins: []\n"},
		{".json", `{"plugins":[]}`},
		{".toml", "plugins = []\n"},
	} {
		t.Run(tc.extension, func(t *testing.T) {
			dir := t.TempDir()
			executable := writeServiceConfigFixture(t, filepath.Join(dir, "mosdns"), "placeholder binary")
			want := writeServiceConfigFixture(t, filepath.Join(dir, "config"+tc.extension), tc.contents)
			wd, configPath, err := resolveServicePaths(executable, dir, "")
			if err != nil || wd != dir || configPath != want {
				t.Fatalf("resolved = %q, %q, %v; want %q", wd, configPath, err, want)
			}
		})
	}
}

func TestResolveServicePathsRejectsMissingOrInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	executable := writeServiceConfigFixture(t, filepath.Join(dir, "mosdns"), "placeholder binary")
	invalid := writeServiceConfigFixture(t, filepath.Join(dir, "invalid.yaml"), "plugins: [\n")
	for _, tc := range []struct{ name, workingDir, config string }{
		{"no default config", dir, ""},
		{"missing config", dir, "missing.yaml"},
		{"config is directory", dir, dir},
		{"working directory is file", executable, "config.yaml"},
		{"working directory missing", filepath.Join(dir, "missing"), "config.yaml"},
		{"malformed config", dir, invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := resolveServicePaths(executable, tc.workingDir, tc.config); err == nil {
				t.Fatal("invalid installation paths were accepted")
			}
		})
	}
}

func writeServiceConfigFixture(t *testing.T, path, contents string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func serviceUnitDirective(t *testing.T, unit, name string) string {
	t.Helper()
	prefix := name + "="
	var values []string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, prefix) {
			values = append(values, strings.TrimPrefix(line, prefix))
		}
	}
	if len(values) != 1 {
		t.Fatalf("unit contains %d %s directives, want one", len(values), name)
	}
	return values[0]
}

// v247 reads these directives as raw scalars, not C-style quoted words.
// Only literal percent specifiers are decoded here.
func serviceUnitScalar(t *testing.T, unit, name string) string {
	t.Helper()
	return strings.ReplaceAll(serviceUnitDirective(t, unit, name), "%%", "%")
}

// Only ExecStart has C-style word parsing. '@' separates the executable from
// argv[0]; dollar escaping applies to arguments, not the executable path.
// Credential environment substitution is left for the real service manager.
func serviceExecWords(t *testing.T, value string) []string {
	t.Helper()
	if !strings.HasPrefix(value, "@") {
		t.Fatalf("ExecStart lacks the '@' prefix that sets argv[0]: %q", value)
	}
	value = strings.TrimPrefix(value, "@")
	words := regexp.MustCompile(`"(?:\\.|[^"\\])*"|[^\s]+`).FindAllString(value, -1)
	for i, word := range words {
		if strings.HasPrefix(word, `"`) {
			decoded, err := strconv.Unquote(word)
			if err != nil {
				t.Fatalf("invalid quoted unit word %q: %v", word, err)
			}
			word = decoded
		}
		word = strings.ReplaceAll(word, "%%", "%")
		if i > 0 {
			word = strings.ReplaceAll(word, "$$", "$")
		}
		words[i] = word
	}
	return words
}
