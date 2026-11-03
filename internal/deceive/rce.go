package deceive

import (
	"net/http"
	"strings"
)

// rceHandler returns fake command output for command-injection probes.
// No real commands are ever executed; all output is static or template-generated.
type rceHandler struct{}

func (h *rceHandler) handle(w http.ResponseWriter, r *http.Request, sessionIP string) error {
	cmd := extractInjectedCommand(r)
	output := fakeCommandOutput(cmd, sessionIP)

	backendHeaders(w)
	w.WriteHeader(http.StatusOK)
	return jsonEncode(w, map[string]interface{}{
		"status": "success",
		"output": output,
	})
}

// extractInjectedCommand finds the command the attacker tried to inject.
// It looks for common shell injection markers (;, &&, |, backtick, $()) and
// returns everything after the first marker as the injected command.
func extractInjectedCommand(r *http.Request) string {
	markers := []string{"; ", ";", " | ", "| ", "&& ", "|| ", "`", "$("}
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			for _, m := range markers {
				if idx := strings.Index(v, m); idx >= 0 {
					cmd := strings.TrimSpace(v[idx+len(m):])
					cmd = strings.TrimRight(cmd, "`)")
					// Take only the first sub-command.
					for _, m2 := range markers {
						if idx2 := strings.Index(cmd, m2); idx2 >= 0 {
							cmd = cmd[:idx2]
						}
					}
					return strings.TrimSpace(cmd)
				}
			}
		}
	}
	return "id" // default if no marker found
}

// fakeCommandOutput returns a plausible fake output string for a given command.
func fakeCommandOutput(cmd, sessionIP string) string {
	parts := strings.Fields(strings.ToLower(strings.TrimSpace(cmd)))
	if len(parts) == 0 {
		return ""
	}
	base := parts[0]

	// Strip leading path components (e.g. /usr/bin/id → id).
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}

	switch base {
	case "id":
		return "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
	case "whoami":
		return "www-data"
	case "hostname", "uname":
		if base == "hostname" {
			return "webapp-server"
		}
		return "Linux webapp-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
	case "pwd":
		return "/var/www/html"
	case "ls":
		return "index.php\nconfig.php\nupload.php\nassets\nvendor\nREADME.md"
	case "cat":
		if len(parts) > 1 {
			arg := strings.Join(parts[1:], " ")
			if strings.Contains(arg, "passwd") {
				return generateFakePasswd(sessionIP)
			}
			if strings.Contains(arg, "shadow") {
				return "cat: " + arg + ": Permission denied"
			}
			if strings.Contains(arg, "hosts") {
				return fakeHosts()
			}
		}
		if len(parts) > 1 {
			return "cat: " + strings.Join(parts[1:], " ") + ": No such file or directory"
		}
		return ""
	case "ps":
		return `  PID TTY          TIME CMD
    1 ?        00:00:02 apache2
  201 ?        00:00:00 apache2
  202 ?        00:00:00 apache2
  203 ?        00:00:00 apache2
  312 pts/0    00:00:00 sh`
	case "env", "printenv", "export":
		return fakeEnviron()
	case "ifconfig", "ip":
		return `eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.0.10  netmask 255.255.255.0  broadcast 10.0.0.255
        inet6 fe80::1  prefixlen 64  scopeid 0x20<link>
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0`
	case "netstat", "ss":
		return `Proto Recv-Q Send-Q Local Address     Foreign Address    State
tcp        0      0 0.0.0.0:80        0.0.0.0:*          LISTEN
tcp        0      0 0.0.0.0:443       0.0.0.0:*          LISTEN
tcp        0      0 0.0.0.0:22        0.0.0.0:*          LISTEN`
	case "find":
		return `/var/www/html/index.php
/var/www/html/config.php
/var/www/html/upload.php
/var/www/html/assets/style.css
/var/www/html/vendor/autoload.php`
	case "wget", "curl":
		return base + ": command disabled by security policy"
	case "python", "python3", "perl", "ruby", "php", "nc", "ncat", "bash", "sh":
		return base + ": command restricted by security policy"
	case "sudo":
		return "sudo: no tty present and no askpass program specified"
	case "su":
		return "su: must be run from a terminal"
	default:
		return "sh: 1: " + base + ": not found"
	}
}
