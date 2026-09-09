package scanner

import (
	"net"
	"regexp"
	"strings"
	"sync"

	"agente-seguridad/internal/models"
)

// subdomainList is a curated list of prefixes to probes. A subset of the
// original 500+ entries is embedded to keep the binary lean while preserving
// coverage of the most common and risky prefixes.
var subdomainList = []string{
	"www", "api", "dev", "stage", "staging", "test", "testing", "beta", "alpha",
	"demo", "preprod", "production", "prod", "live", "uat", "qa", "sandbox",
	"admin", "administrator", "dashboard", "panel", "console", "control",
	"portal", "gateway", "proxy", "cdn", "media", "static", "assets",
	"images", "img", "css", "js", "files", "downloads", "uploads",
	"blog", "news", "forum", "community", "support", "help", "faq",
	"docs", "documentation", "wiki", "kb", "knowledgebase",
	"shop", "store", "cart", "checkout", "payment", "payments",
	"account", "accounts", "user", "users", "profile",
	"login", "signin", "signup", "register", "auth", "oauth",
	"mail", "email", "smtp", "pop3", "imap", "webmail",
	"ftp", "sftp", "ssh", "shell", "terminal",
	"monitoring", "monitor", "metrics", "stats", "status",
	"analytics", "report", "reports", "data", "database",
	"v1", "v2", "v3", "v4", "v5", "api2", "api3",
	"old", "new", "backup", "backups", "archive", "archives",
	"temp", "tmp", "cache", "sessions", "logs", "log",
	"services", "service", "server", "servers", "host", "app", "web",
	"mobile", "secure", "security", "ssl", "tls", "cert",
	"private", "internal", "intranet", "extranet", "vpn", "remote",
	"partner", "partners", "vendor", "vendors", "career", "careers", "jobs",
	"legal", "privacy", "about", "contact", "team",
	"investor", "press", "sales", "marketing", "crm", "erp", "bi",
	"research", "engineering", "devops", "platform", "infrastructure",
	"network", "dns", "dhcp", "router", "firewall", "storage", "cloud",
	"chat", "messaging", "notification", "search", "index", "catalog",
	"mail", "smtp", "health", "status", "gateway", "kubernetes", "k8s",
	"ci", "cd", "jenkins", "gitlab", "github", "bitbucket", "git",
	"sonar", "jira", "confluence", "grafana", "prometheus", "kibana",
	"elastic", "elasticsearch", "redis", "mongodb", "mysql", "postgres",
	"db", "database", "etl", "kafka", "spark", "hadoop",
	"webhook", "hooks", "callback", "events", "queue", "rabbitmq",
	"s3", "bucket", "files", "assets", "static", "blob",
	"graphql", "rest", "soap", "xmlrpc", "jsonrpc", "odata",
	"tools", "tool", "devtools", "debug", "staging", "uat", "sandbox",
	"ftp", "sftp", "stun", "turn", "voip", "meet", "video", "live",
	"ads", "adserver", "tracker", "crm", "erp", "intranet", "office",
	"api-dev", "api-staging", "api-test", "api-uat", "api-demo", "api-sandbox",
	"dev-api", "staging-api", "test-api", "uat-api", "demo-api", "sandbox-api",
}

// takeoverPatterns maps a known third-party service to an observable body
// signature that indicates the subdomain is unclaimed (takeover possible).
var takeoverPatterns = map[string][]string{
	"Heroku":       {"No such app", "Application error"},
	"GitHub Pages": {"There isn't a GitHub Pages site here.", "Page not found"},
	"Netlify":      {"Netlify", "Not Found"},
	"Azure":        {"404 Web Site not found", "resource you are looking for has been removed"},
	"CloudFront":   {"The resource could not be found.", "CloudFront"},
	"AWS S3":       {"NoSuchBucket", "The specified bucket does not exist"},
	"Firebase":     {"The requested URL was not found"},
	"Vercel":       {"The requested URL was not found", "Not Found"},
	"Render":       {"Not Found"},
	"Fly.io":       {"The requested URL was not found"},
	"Railway":      {"Not Found"},
	"Replit":       {"The requested URL was not found"},
	"Surge.sh":     {"project not found"},
}

var ipRe = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// CheckSubdomain resolves a single subdomain and probes its HTTP response.
func CheckSubdomain(sub, domain string) models.Subdominio {
	full := sub + "." + domain
	if sub == "" {
		full = domain
	}
	res := models.Subdominio{Subdominio: sub, DominioCompleto: full}

	ips, err := net.LookupHost(full)
	if err == nil && len(ips) > 0 {
		res.IP = ips[0]
	}

	if cname, err := net.LookupCNAME(full); err == nil {
		res.CNAME = strings.TrimSuffix(cname, ".")
	}

	body := ""
	status := 0
	for _, proto := range []string{"https", "http"} {
		req, e := httpReq(proto + "://" + full)
		if e != nil {
			continue
		}
		resp, e := Client(5).Do(req)
		if e != nil {
			continue
		}
		status = resp.StatusCode
		body = readBody(resp)
		resp.Body.Close()
		break
	}

	res.HTTPStatus = status
	if status == 200 {
		res.Existe = true
	} else if status >= 301 && status <= 308 {
		res.Existe = true
	} else if status == 401 || status == 403 {
		res.Existe = true
	}

	// Look for takeover signatures in observed content.
	for service, sigs := range takeoverPatterns {
		for _, sig := range sigs {
			if body != "" && strings.Contains(body, sig) {
				res.TakeoverPosible = true
				res.Servicio = service
				break
			}
		}
		if res.TakeoverPosible {
			break
		}
	}
	return res
}

// ScanSubdomains probes all subdomain prefixes for a domain concurrently.
func ScanSubdomains(domain string, workers int) models.SubdomainResult {
	res := models.SubdomainResult{Dominio: domain, SubdominiosAnalizados: []models.Subdominio{}, Vulnerabilidades: []models.Vulnerabilidad{}}
	if workers <= 0 {
		workers = 30
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	seen := map[string]bool{}
	for _, sub := range subdomainList {
		if seen[sub] {
			continue
		}
		seen[sub] = true
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if s == "" {
				return
			}
			r := CheckSubdomain(s, domain)
			mu.Lock()
			res.SubdominiosAnalizados = append(res.SubdominiosAnalizados, r)
			if r.Existe {
				res.TotalSubdominiosEncontrados++
			}
			if r.TakeoverPosible {
				res.TotalTakeovers++
				res.Vulnerabilidades = append(res.Vulnerabilidades, models.Vulnerabilidad{
					Tipo: "Subdomain Takeover", Severidad: "Alta",
					Evidencia: r.DominioCompleto + " -> " + r.Servicio,
					Parametro: r.DominioCompleto, URL: r.DominioCompleto,
				})
			}
			mu.Unlock()
		}(sub)
	}
	wg.Wait()
	return res
}
