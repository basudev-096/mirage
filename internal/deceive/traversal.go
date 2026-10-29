package deceive

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/brianvoe/gofakeit/v6"
)

// traversalHandler returns plausible fake file content for path-traversal probes.
// No real files are ever read; all content is synthetically generated.
type traversalHandler struct{}

func (h *traversalHandler) handle(w http.ResponseWriter, r *http.Request, sessionIP string) error {
	target := extractTraversalTarget(r)

	var body, contentType string
	switch {
	case containsAny(target, "/etc/passwd", "etc/passwd"):
		body = generateFakePasswd(sessionIP)
		contentType = "text/plain"
	case containsAny(target, "/etc/shadow", "etc/shadow"):
		// Pretend permission was denied — realistic for www-data process.
		body = "cat: /etc/shadow: Permission denied\n"
		contentType = "text/plain"
	case containsAny(target, "/etc/hosts", "etc/hosts"):
		body = fakeHosts()
		contentType = "text/plain"
	case containsAny(target, "proc/self/environ", "/proc/self/environ"):
		body = fakeEnviron()
		contentType = "text/plain"
	case containsAny(target, "proc/self/cmdline", "/proc/self/cmdline"):
		body = "/usr/sbin/apache2\x00-k\x00start\x00"
		contentType = "text/plain"
	case containsAny(target, ".env"):
		body = generateFakeEnvFile(sessionIP)
		contentType = "text/plain"
	case containsAny(target, "web.xml"):
		body = fakeWebXML()
		contentType = "application/xml"
	case containsAny(target, "web.config"):
		body = fakeWebConfig()
		contentType = "application/xml"
	case containsAny(target, "config.php", "database.php", "settings.php"):
		body = generateFakePHPConfig(sessionIP)
		contentType = "text/plain"
	default:
		// Generic "not found" that looks like a real OS error.
		body = fmt.Sprintf("cat: %s: No such file or directory\n", target)
		contentType = "text/plain"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Backend-Server", "mirage-demo-backend")
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprint(w, body)
	return err
}

// extractTraversalTarget pulls the first query-param value that looks like a
// path traversal (contains ".." or an absolute path prefix).
func extractTraversalTarget(r *http.Request) string {
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if strings.Contains(v, "..") ||
				strings.HasPrefix(v, "/etc/") ||
				strings.HasPrefix(v, "/proc/") ||
				strings.HasPrefix(v, "/var/") {
				return v
			}
		}
	}
	return r.URL.Path
}

func containsAny(s string, subs ...string) bool {
	sl := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(sl, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// generateFakePasswd generates a realistic-looking /etc/passwd using synthetic data.
func generateFakePasswd(sessionIP string) string {
	f := gofakeit.New(seedFor(sessionIP, "passwd"))
	var sb strings.Builder

	// Fixed well-known system accounts — always present.
	type sysEntry struct{ user, uid, gid, home, shell string }
	sysEntries := []sysEntry{
		{"root", "0", "0", "/root", "/bin/bash"},
		{"daemon", "1", "1", "/usr/sbin", "/usr/sbin/nologin"},
		{"bin", "2", "2", "/bin", "/usr/sbin/nologin"},
		{"sys", "3", "3", "/dev", "/usr/sbin/nologin"},
		{"sync", "4", "65534", "/bin", "/bin/sync"},
		{"www-data", "33", "33", "/var/www", "/usr/sbin/nologin"},
		{"backup", "34", "34", "/var/backups", "/usr/sbin/nologin"},
		{"nobody", "65534", "65534", "/nonexistent", "/usr/sbin/nologin"},
	}
	for _, e := range sysEntries {
		sb.WriteString(fmt.Sprintf("%s:x:%s:%s:%s:%s:%s\n",
			e.user, e.uid, e.gid, e.user, e.home, e.shell))
	}

	// 3–5 randomly generated regular users.
	numUsers := f.Number(3, 5)
	for i := 0; i < numUsers; i++ {
		uid := 1000 + i
		username := strings.ToLower(f.Username())
		gecos := f.Name()
		home := "/home/" + username
		sb.WriteString(fmt.Sprintf("%s:x:%d:%d:%s:%s:/bin/bash\n",
			username, uid, uid, gecos, home))
	}
	return sb.String()
}

func fakeHosts() string {
	return `127.0.0.1	localhost
127.0.1.1	webapp-server
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
10.0.0.1	db-primary.internal
10.0.0.2	db-replica.internal
10.0.0.3	redis.internal
`
}

func fakeEnviron() string {
	pairs := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOSTNAME=webapp-server",
		"USER=www-data",
		"HOME=/var/www",
		"APACHE_RUN_USER=www-data",
		"APACHE_RUN_GROUP=www-data",
		"APACHE_LOG_DIR=/var/log/apache2",
		"DOCUMENT_ROOT=/var/www/html",
		"PWD=/var/www/html",
	}
	return strings.Join(pairs, "\x00") + "\x00"
}

func generateFakeEnvFile(sessionIP string) string {
	f := gofakeit.New(seedFor(sessionIP, "envfile"))
	appKey := "base64:" + f.LetterN(44)
	dbPass := f.Password(true, true, true, false, false, 20)
	redisPass := f.LetterN(24)
	return fmt.Sprintf(`APP_NAME="WebApplication"
APP_ENV=production
APP_KEY=%s
APP_DEBUG=false
APP_URL=https://example.com

DB_CONNECTION=mysql
DB_HOST=db-primary.internal
DB_PORT=3306
DB_DATABASE=app_db
DB_USERNAME=app_user
DB_PASSWORD=%s

REDIS_HOST=redis.internal
REDIS_PASSWORD=%s
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.mailgun.org
MAIL_PORT=587
MAIL_ENCRYPTION=tls
`, appKey, dbPass, redisPass)
}

func generateFakePHPConfig(sessionIP string) string {
	f := gofakeit.New(seedFor(sessionIP, "phpconfig"))
	return fmt.Sprintf(`<?php
define('DB_HOST',     'db-primary.internal');
define('DB_NAME',     'app_db');
define('DB_USER',     'app_user');
define('DB_PASS',     '%s');
define('SECRET_KEY',  '%s');
define('ENVIRONMENT', 'production');
`, f.Password(true, true, true, false, false, 20), f.LetterN(32))
}

func fakeWebXML() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.1" xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <display-name>WebApplication</display-name>
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>/WEB-INF/applicationContext.xml</param-value>
  </context-param>
  <listener>
    <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
  </listener>
  <servlet>
    <servlet-name>dispatcher</servlet-name>
    <servlet-class>org.springframework.web.servlet.DispatcherServlet</servlet-class>
    <load-on-startup>1</load-on-startup>
  </servlet>
  <servlet-mapping>
    <servlet-name>dispatcher</servlet-name>
    <url-pattern>/</url-pattern>
  </servlet-mapping>
</web-app>`
}

func fakeWebConfig() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <system.webServer>
    <rewrite>
      <rules>
        <rule name="Redirect to HTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="off" ignoreCase="true" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
      </rules>
    </rewrite>
  </system.webServer>
</configuration>`
}
