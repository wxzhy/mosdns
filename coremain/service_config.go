package coremain

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kardianos/service"
	"github.com/spf13/viper"
)

const maxServiceCredentialSize = 1_000_000

func newServiceConfig() *service.Config {
	return &service.Config{
		Name:        "mosdns",
		DisplayName: "mosdns",
		Description: "A DNS forwarder",
	}
}

// DynamicUser may reuse a static NSS account. Check the actual identity before
// opening listeners even if an existing mosdns account was mapped to UID/GID 0.
func validateServiceIdentity(platform string, uid, gid int) error {
	if platform == "linux-systemd" && (uid <= 0 || gid <= 0) {
		return fmt.Errorf("refusing to run the systemd service with UID %d/GID %d; reinstall the low-privilege unit and use a non-root mosdns account/group", uid, gid)
	}
	return nil
}

// resolveServicePaths fixes paths without changing the installer's cwd. Reading
// the config also preserves Viper's supported formats and default-file lookup.
// No plugins, listeners or probes are started during installation.
func resolveServicePaths(executable, dir, config string) (workingDir, configPath string, err error) {
	if dir == "" {
		dir = filepath.Dir(executable)
	}
	workingDir, err = filepath.Abs(dir)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve service working directory, %w", err)
	}
	// Resolve directory symlinks so a path under /opt cannot conceal a target
	// inside ProtectHome's /home or /root mounts.
	workingDir, err = filepath.EvalSymlinks(workingDir)
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve service working directory, %w", err)
	}
	info, err := os.Stat(workingDir)
	if err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("service working directory is not a directory: %s", workingDir)
	}
	v := viper.New()
	if config == "" {
		v.SetConfigName("config")
		v.AddConfigPath(workingDir)
	} else {
		if !filepath.IsAbs(config) {
			config = filepath.Join(workingDir, config)
		}
		v.SetConfigFile(config)
	}
	if err := v.ReadInConfig(); err != nil {
		return "", "", fmt.Errorf("cannot read service config, %w", err)
	}
	configPath, err = filepath.Abs(v.ConfigFileUsed())
	if err != nil {
		return "", "", fmt.Errorf("cannot resolve service config path, %w", err)
	}
	info, err = os.Stat(configPath)
	if err != nil || !info.Mode().IsRegular() {
		return "", "", fmt.Errorf("service config is not a regular file: %s", configPath)
	}
	return workingDir, configPath, nil
}

// Build a fresh config for installation: an unsupported backend must never
// silently fall back to a service running as root/LocalSystem.
func newLowPrivilegeServiceConfig(platform, executable, workingDir, configPath string) (*service.Config, error) {
	cfg := newServiceConfig()
	cfg.Executable = executable
	cfg.Arguments = []string{"start", "--as-service", "-d", workingDir, "-c", configPath}
	switch {
	case strings.HasPrefix(platform, "windows-"):
		cfg.UserName = `NT AUTHORITY\LocalService`
	case platform == "linux-systemd":
		unit, err := renderSystemdService(executable, workingDir, configPath)
		if err != nil {
			return nil, err
		}
		credential, err := serviceCredentialName(configPath)
		if err != nil {
			return nil, err
		}
		cfg.UserName = "mosdns"
		cfg.WorkingDirectory = workingDir
		cfg.Arguments[len(cfg.Arguments)-1] = "${CREDENTIALS_DIRECTORY}/" + credential
		cfg.Option = service.KeyValue{"SystemdScript": unit}
	default:
		return nil, fmt.Errorf("low-privilege service installation is not supported by %q; use systemd >= 247 on Linux or scripts/openwrt/mosdns-init-openwrt on OpenWrt", platform)
	}
	return cfg, nil
}

func validateSystemdVersion(output string) error {
	firstLine, _, _ := strings.Cut(strings.TrimSpace(output), "\n")
	fields := strings.Fields(firstLine)
	if len(fields) >= 2 && fields[0] == "systemd" {
		version, err := strconv.Atoi(fields[1])
		if err == nil && version >= 247 {
			return nil
		}
	}
	return fmt.Errorf("low-privilege service installation requires systemd >= 247 for DynamicUser and LoadCredential")
}

func serviceCredentialName(configPath string) (string, error) {
	ext := strings.ToLower(path.Ext(configPath))
	if len(ext) < 2 {
		return "", fmt.Errorf("service config must have a supported file extension")
	}
	for _, r := range ext[1:] {
		if r < 'a' || r > 'z' {
			return "", fmt.Errorf("invalid service config file extension %q", ext)
		}
	}
	return "config" + ext, nil
}

func validateSystemdValue(value string) error {
	if !utf8.ValidString(value) {
		return fmt.Errorf("service path is not valid UTF-8")
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("service path contains a control character")
		}
	}
	return nil
}

// systemdWord quotes an ExecStart word. C escapes apply here, unlike scalar
// directives. Encode braces so the library's mini-template cannot parse paths.
func systemdWord(value string) (string, error) {
	if err := validateSystemdValue(value); err != nil {
		return "", err
	}
	value = strings.ReplaceAll(value, "%", "%%")
	quoted := strconv.Quote(value)
	return strings.NewReplacer("{", `\x7b`, "}", `\x7d`).Replace(quoted), nil
}

// WorkingDirectory and the LoadCredential source are raw scalar values in
// systemd 247: surrounding quotes and C escapes would change the actual path.
func systemdScalar(value string) (string, error) {
	if err := validateSystemdValue(value); err != nil {
		return "", err
	}
	if strings.TrimSpace(value) != value || strings.HasSuffix(value, `\`) || strings.Contains(value, "{{") {
		return "", fmt.Errorf("service directory/config path cannot end in whitespace or a backslash, or contain '{{'")
	}
	return strings.ReplaceAll(value, "%", "%%"), nil
}

func renderSystemdService(executable, workingDir, configPath string) (string, error) {
	for _, entry := range []struct{ name, value string }{
		{"executable", executable}, {"working directory", workingDir}, {"config", configPath},
	} {
		if !path.IsAbs(entry.value) {
			return "", fmt.Errorf("systemd service %s must be an absolute path", entry.name)
		}
		if entry.name != "config" {
			cleaned := path.Clean(entry.value)
			for _, hidden := range []string{"/root", "/home", "/run/user"} {
				if cleaned == hidden || strings.HasPrefix(cleaned, hidden+"/") {
					return "", fmt.Errorf("systemd service %s is hidden by ProtectHome: %s; deploy outside /root, /home and /run/user", entry.name, entry.value)
				}
			}
		}
	}
	credential, err := serviceCredentialName(configPath)
	if err != nil {
		return "", err
	}
	exe, err := systemdWord(executable)
	if err != nil {
		return "", err
	}
	wd, err := systemdScalar(workingDir)
	if err != nil {
		return "", err
	}
	wdArgument, err := systemdWord(strings.ReplaceAll(workingDir, "$", "$$"))
	if err != nil {
		return "", err
	}
	credentialSource, err := systemdScalar(credential + ":" + configPath)
	if err != nil {
		return "", err
	}
	// The @ prefix supplies a fixed argv[0], so a $ in the executable path is
	// neither expanded in argv[0] nor doubled in command->path. Literal arguments
	// escape $, while only the credential uses manager-provided env expansion.
	// ${CREDENTIALS_DIRECTORY} works on systemd 247; the newer %d does not.
	return fmt.Sprintf(`[Unit]
Description=A DNS forwarder
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
User=mosdns
DynamicUser=yes
WorkingDirectory=%s
LoadCredential=%s
ExecStart=@%s mosdns start --as-service -d %s -c "${CREDENTIALS_DIRECTORY}/%s"
Environment=HOME=/var/lib/mosdns
StateDirectory=mosdns
StateDirectoryMode=0750
LogsDirectory=mosdns
LogsDirectoryMode=0750
RuntimeDirectory=mosdns
RuntimeDirectoryMode=0750
UMask=0027
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectProc=invisible
ProtectClock=true
ProtectHostname=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_PACKET AF_NETLINK
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
Restart=on-failure
RestartSec=3
TimeoutStopSec=35

[Install]
WantedBy=multi-user.target
`, wd, credentialSource, exe, wdArgument, credential), nil
}
