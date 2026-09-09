package scanner

import (
	"crypto/md5"
	"encoding/hex"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/net/html"

	"agente-seguridad/internal/models"
)

// sourcePatterns maps a category to regex and metadata for source-code scanning.
type sourcePattern struct {
	RE          *regexp.Regexp
	Description string
	Severity    string
}

var sourcePatterns = []struct {
	Name string
	P    sourcePattern
}{
	{"aws_key", sourcePattern{regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS Access Key ID", "Crítica"}},
	{"aws_secret", sourcePattern{regexp.MustCompile(`\b[0-9a-zA-Z/+]{40}\b`), "AWS Secret Access Key", "Crítica"}},
	{"google_api", sourcePattern{regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "Google API Key", "Crítica"}},
	{"github_token", sourcePattern{regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), "GitHub Personal Access Token", "Crítica"}},
	{"gitlab_token", sourcePattern{regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`), "GitLab Personal Access Token", "Crítica"}},
	{"stripe_key", sourcePattern{regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24}`), "Stripe Secret Key", "Crítica"}},
	{"twilio_key", sourcePattern{regexp.MustCompile(`SK[0-9a-f]{32}`), "Twilio API Key", "Alta"}},
	{"jwt_token", sourcePattern{regexp.MustCompile(`eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`), "JWT Token", "Alta"}},
	{"password_in_code", sourcePattern{regexp.MustCompile(`(?i)(password|passwd|pwd|contraseña|clave)\s*[=:]\s*["']([^"'\s]+)["']`), "Contraseña en código", "Alta"}},
	{"username_in_code", sourcePattern{regexp.MustCompile(`(?i)(username|user|usuario|login)\s*[=:]\s*["']([^"'\s]+)["']`), "Usuario en código", "Media"}},
	{"email_in_code", sourcePattern{regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`), "Email en código", "Baja"}},
	{"database_url", sourcePattern{regexp.MustCompile(`(?i)(mysql|postgres|mongodb|redis|sqlite)://[^\s"'` + "`" + `]+`), "URL de Base de Datos", "Alta"}},
	{"internal_url", sourcePattern{regexp.MustCompile(`(?i)(http|https)://[^\s"']+\.(local|internal|dev|staging|test|intranet)`), "URL Interna", "Media"}},
	{"private_ip", sourcePattern{regexp.MustCompile(`\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\]`), "IP Privada", "Media"}},
	{"env_var", sourcePattern{regexp.MustCompile(`(?i)(SECRET_KEY|API_KEY|DATABASE_URL|REDIS_URL|JWT_SECRET|SIGNING_KEY|ENCRYPTION_KEY)\s*=\s*["']([^"']+)["']`), "Variable de Entorno", "Alta"}},
	{"eval_code", sourcePattern{regexp.MustCompile(`\beval\s*\(`), "Uso de eval()", "Media"}},
	{"exec_code", sourcePattern{regexp.MustCompile(`\bexec\s*\(`), "Uso de exec()", "Media"}},
	{"system_call", sourcePattern{regexp.MustCompile(`\bsystem\s*\(`), "Uso de system()", "Media"}},
	{"comment_todo", sourcePattern{regexp.MustCompile(`(//|#|<!--)\s*(TODO|FIXME|BUG|HACK|XXX|SECURITY|REVIEW|WARNING|DEPRECATED)`), "Comentario de Desarrollo", "Baja"}},
}

// excludedWords reduce false positives for generic identifiers.
var excludedWords = map[string]bool{
	"undefined": true, "null": true, "false": true, "true": true, "function": true,
	"return": true, "var": true, "let": true, "const": true, "class": true,
	"interface": true, "module": true, "require": true, "import": true,
	"export": true, "default": true, "test": true, "demo": true, "example": true,
}

// AnalyzeSourceCode scans the page HTML and linked JS/CSS for sensitive data.
func AnalyzeSourceCode(rawURL string, workers int) models.SourceResult {
	res := models.SourceResult{URL: rawURL, Encontrados: map[string][]models.Hallazgo{}, Vulnerabilidades: []models.Vulnerabilidad{}}
	body := safeGetBody(rawURL)
	if body == "" {
		return res
	}

	analyzeText(body, "HTML", &res)
	links := extractLinks(body, rawURL)

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, l := range links {
		wg.Add(1)
		go func(link string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cb := safeGetBody(link)
			if cb == "" {
				return
			}
			mu.Lock()
			res.ArchivosAnalizados++
			mu.Unlock()
			analyzeText(cb, link, &res)
		}(l)
	}
	wg.Wait()

	for cat, items := range res.Encontrados {
		res.Total += len(items)
		for _, it := range items {
			if sev := severityFor(cat); sev == "Crítica" || sev == "Alta" {
				res.Vulnerabilidades = append(res.Vulnerabilidades, models.Vulnerabilidad{
					Tipo: it.Descripcion, Severidad: sev, Evidencia: it.Valor, URL: rawURL,
					Parametro: cat,
				})
				break
			}
		}
	}
	return res
}

func analyzeText(text, source string, res *models.SourceResult) {
	for _, sp := range sourcePatterns {
		for _, m := range sp.P.RE.FindAllString(text, -1) {
			v := strings.TrimSpace(m)
			if len(v) < 4 || isExcluded(v) {
				continue
			}
			hash := hashVal(v)
			it := models.Hallazgo{
				Categoria: sp.Name, Descripcion: sp.P.Description, Valor: truncateStr(v, 200),
				Fuente: source, Severidad: sp.P.Severity, Hash: hash,
			}
			res.Encontrados[sp.Name] = append(res.Encontrados[sp.Name], it)
		}
	}
}

func severityFor(cat string) string {
	for _, sp := range sourcePatterns {
		if sp.Name == cat {
			return sp.P.Severity
		}
	}
	return "Media"
}

func isExcluded(v string) bool {
	lv := strings.ToLower(v)
	for w := range excludedWords {
		if w == lv {
			return true
		}
	}
	return strings.Contains(lv, "your_") || strings.Contains(lv, "my_") || strings.Contains(lv, "example_") || strings.Contains(lv, "demo_") || strings.Contains(lv, "test_") || strings.Contains(lv, "sample_")
}

func hashVal(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}

// extractLinks gathers local JS/CSS resources (and skips well-known CDNs).
func extractLinks(body, base string) []string {
	var out []string
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		resource := ""
		isJS := false
		switch tok.Data {
		case "script":
			for _, a := range tok.Attr {
				if a.Key == "src" {
					resource = a.Val
					isJS = true
				}
			}
		case "link":
			for _, a := range tok.Attr {
				if a.Key == "href" && strings.Contains(a.Val, ".css") {
					resource = a.Val
				}
			}
		}
		if resource == "" || strings.HasPrefix(resource, "data:") {
			continue
		}
		if !strings.HasPrefix(resource, "http") {
			resource = strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(resource, "/")
		}
		if isCDN(resource) {
			continue
		}
		if isJS || strings.Contains(resource, ".css") {
			out = append(out, resource)
		}
	}
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

func isCDN(u string) bool {
	for _, s := range []string{"google-analytics", "googleapis", "gstatic", "cloudflare", "facebook.net", "twitter.com", "cdnjs", "jquery", "bootstrap", "fontawesome", "popper", "axios", "vue", "react", "angular", "moment", "lodash", "underscore", "d3", "chart"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}
