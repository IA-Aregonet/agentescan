package scanner

import (
	"bytes"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"agente-seguridad/internal/models"
)

// ===================== CSRF =====================

var tokenRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)csrf`), regexp.MustCompile(`(?i)xsrf`), regexp.MustCompile(`(?i)token`),
	regexp.MustCompile(`(?i)nonce`), regexp.MustCompile(`(?i)form_build_id`),
	regexp.MustCompile(`__RequestVerificationToken`), regexp.MustCompile(`csrfmiddlewaretoken`),
}

// AnalyzeCSRF scans forms for CSRF tokens.
func AnalyzeCSRF(rawURL string) models.CSRFResult {
	res := models.CSRFResult{URL: rawURL, Recomendaciones: []string{}}
	body := safeGetBody(rawURL)
	if body == "" {
		return res
	}

	forms := parseForms(body)
	if len(forms) == 0 {
		res.Recomendaciones = append(res.Recomendaciones, "No se encontraron formularios")
		return res
	}

	for _, inputs := range forms {
		hasToken := false
		for _, name := range inputs {
			for _, r := range tokenRe {
				if r.MatchString(name) {
					hasToken = true
					break
				}
			}
			if hasToken {
				break
			}
		}
		if hasToken {
			res.CSRFProtegidos++
		} else {
			res.CSRFVulnerables++
		}
	}

	if res.CSRFVulnerables > 0 {
		res.Recomendaciones = append(res.Recomendaciones,
			"⚠️ "+itoa(res.CSRFVulnerables)+" formularios sin protección CSRF")
	}
	return res
}

func parseForms(htmlStr string) [][]string {
	var forms [][]string
	z := html.NewTokenizer(strings.NewReader(htmlStr))
	var cur []string
	depth := 0
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			tok := z.Token()
			switch strings.ToLower(tok.Data) {
			case "form":
				depth++
				cur = []string{}
			case "input":
				name := ""
				for _, a := range tok.Attr {
					if a.Key == "name" {
						name = a.Val
					}
				}
				if cur != nil && name != "" {
					cur = append(cur, name)
				}
			}
		}
		if tt == html.EndTagToken {
			tok := z.Token()
			if strings.ToLower(tok.Data) == "form" {
				if cur != nil {
					forms = append(forms, cur)
				}
				cur = nil
				depth--
			}
		}
	}
	return forms
}

// ===================== GraphQL =====================

// AnalyzeGraphQL probes for a GraphQL endpoint.
func AnalyzeGraphQL(rawURL string) models.GraphQLResult {
	res := models.GraphQLResult{URL: rawURL, Vulnerabilidades: []models.Vulnerabilidad{}}
	client := Client(10)
	req, err := http.NewRequest(http.MethodPost, rawURL, bytes.NewReader([]byte(
		`{"query":"query { __typename }"}`)))
	if err != nil {
		return res
	}
	req.Header = BaseHeaders()
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return res
	}
	body := readBody(resp)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return res
	}
	if _, ok := parsed["data"]; ok {
		res.EsGraphQL = true
		if strings.Contains(body, "__schema") {
			res.Vulnerabilidades = append(res.Vulnerabilidades, models.Vulnerabilidad{
				Tipo: "GraphQL Introspection Habilitada", Severidad: "Media",
				Evidencia: "El endpoint permite introspection", URL: rawURL,
			})
		}
	}
	return res
}

// ===================== WebSockets =====================

var wsRe = []*regexp.Regexp{
	regexp.MustCompile(`new WebSocket\([` + "`" + `'"]([^` + "`" + `'"]+)[` + "`" + `'"]\)`),
	regexp.MustCompile(`ws://[^\s'"]+`),
	regexp.MustCompile(`wss://[^\s'"]+`),
	regexp.MustCompile(`SocketIO`),
	regexp.MustCompile(`socket\.io`),
}

// AnalyzeWebSocket scans HTML for websocket references.
func AnalyzeWebSocket(rawURL string) models.WebSocketResult {
	res := models.WebSocketResult{URL: rawURL, WebSockets: []string{}, Vulnerabilidades: []models.Vulnerabilidad{}}
	body := safeGetBody(rawURL)
	if body == "" {
		return res
	}
	seen := map[string]bool{}
	for _, r := range wsRe {
		for _, m := range r.FindAllString(body, -1) {
			if !seen[m] {
				seen[m] = true
				res.WebSockets = append(res.WebSockets, m)
				res.TotalEncontrados++
			}
		}
	}
	return res
}

// ===================== Race Conditions =====================

var raceRe = regexp.MustCompile(`(?i)(balance|stock|inventory|quantity|count|limit)`)

// AnalyzeRaceConditions detects sensitive endpoints by keyword.
func AnalyzeRaceConditions(rawURL string) models.RaceResult {
	res := models.RaceResult{URL: rawURL, EndpointsSensibles: []string{}, Vulnerabilidades: []models.Vulnerabilidad{}}
	body := safeGetBody(rawURL)
	for _, m := range raceRe.FindAllString(body, -1) {
		res.EndpointsSensibles = append(res.EndpointsSensibles, m)
	}
	return res
}

// ===================== Cache Poisoning =====================

var cacheHeaders = []string{"Cache-Control", "Pragma", "Expires", "X-Cache", "CF-Cache-Status", "X-Varnish-Cache"}

// AnalyzeCachePoisoning inspects caching headers and Host header reflection.
func AnalyzeCachePoisoning(rawURL string) models.CacheResult {
	res := models.CacheResult{URL: rawURL, Vulnerabilidades: []models.Vulnerabilidad{}}
	client := Client(10)
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header = BaseHeaders()
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()

	for _, h := range cacheHeaders {
		if resp.Header.Get(h) != "" {
			res.UsaCache = true
			break
		}
	}
	switch {
	case resp.Header.Get("CF-Cache-Status") != "":
		res.TipoCache = "Cloudflare"
	case resp.Header.Get("X-Varnish-Cache") != "":
		res.TipoCache = "Varnish"
	case resp.Header.Get("X-Cache") != "":
		res.TipoCache = "Squid/CDN"
	}

	for _, host := range []string{"evil.com", "attacker.com"} {
		req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		req.Header = BaseHeaders()
		req.Host = host
		r, err := client.Do(req)
		if err != nil {
			continue
		}
		body := readBody(r)
		r.Body.Close()
		if strings.Contains(body, host) {
			res.Vulnerabilidades = append(res.Vulnerabilidades, models.Vulnerabilidad{
				Tipo: "Host Header Injection", Severidad: "Alta",
				Evidencia: "El header Host=" + host + " se refleja", URL: rawURL,
			})
			break
		}
	}
	return res
}

// ===================== CORS =====================

var corsOrigins = []string{"https://evil.com", "https://attacker.com", "http://localhost", "null", "*"}

// AnalyzeCORS tests CORS configurations.
func AnalyzeCORS(rawURL string) models.CORSResult {
	res := models.CORSResult{URL: rawURL, Pruebas: []models.PruebaCORS{}, Vulnerabilidades: []models.Vulnerabilidad{}}
	client := Client(10)
	for _, origin := range corsOrigins {
		req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		req.Header = BaseHeaders()
		req.Header.Set("Origin", origin)
		r, err := client.Do(req)
		if err != nil {
			continue
		}
		defer r.Body.Close()
		acao := r.Header.Get("Access-Control-Allow-Origin")
		acac := r.Header.Get("Access-Control-Allow-Credentials")
		switch {
		case acao == "*":
			sev := "Alta"
			desc := "ACAO: *"
			if strings.EqualFold(acac, "true") {
				sev = "Crítica"
				desc = "ACAO: * y ACAC: true"
			}
			res.Vulnerabilidades = append(res.Vulnerabilidades, models.Vulnerabilidad{
				Tipo: "CORS Wildcard", Severidad: sev, Evidencia: desc, Parametro: origin, URL: rawURL,
			})
		case acao == origin:
			res.Vulnerabilidades = append(res.Vulnerabilidades, models.Vulnerabilidad{
				Tipo: "CORS Origin Reflection", Severidad: "Media",
				Evidencia: "Origen " + origin + " reflejado", Parametro: origin, URL: rawURL,
			})
		}
	}
	return res
}

// ===================== Tecnologías =====================

var techPatterns = map[string][]*regexp.Regexp{
	"WordPress":  {regexp.MustCompile(`(?i)wp-content`), regexp.MustCompile(`(?i)wp-includes`), regexp.MustCompile(`(?i)wp-admin`)},
	"Joomla":     {regexp.MustCompile(`(?i)joomla`), regexp.MustCompile(`(?i)components/com_`)},
	"Drupal":     {regexp.MustCompile(`(?i)drupal`), regexp.MustCompile(`(?i)misc/drupal.js`)},
	"Magento":    {regexp.MustCompile(`(?i)magento`), regexp.MustCompile(`(?i)skin/frontend`)},
	"React":      {regexp.MustCompile(`(?i)react-`), regexp.MustCompile(`(?i)react-dom`), regexp.MustCompile(`(?i)__REACT_DEVTOOLS`)},
	"Vue.js":     {regexp.MustCompile(`(?i)vue-`), regexp.MustCompile(`(?i)Vue\.`), regexp.MustCompile(`(?i)vue-router`)},
	"Angular":    {regexp.MustCompile(`(?i)ng-app`), regexp.MustCompile(`(?i)ng-`), regexp.MustCompile(`(?i)angular`)},
	"Laravel":    {regexp.MustCompile(`(?i)laravel`), regexp.MustCompile(`(?i)_token`), regexp.MustCompile(`(?i)csrf_token`)},
	"Django":     {regexp.MustCompile(`(?i)csrftoken`), regexp.MustCompile(`(?i)django`)},
	"Apache":     {regexp.MustCompile(`(?i)apache`)},
	"Nginx":      {regexp.MustCompile(`(?i)nginx`)},
	"PHP":        {regexp.MustCompile(`\.php`), regexp.MustCompile(`(?i)PHPSESSID`), regexp.MustCompile(`<\?php`)},
	"ASP.NET":    {regexp.MustCompile(`\.aspx`), regexp.MustCompile(`__VIEWSTATE`), regexp.MustCompile(`(?i)ASP.NET`)},
	"MySQL":      {regexp.MustCompile(`(?i)mysql`), regexp.MustCompile(`(?i)innodb`)},
	"PostgreSQL": {regexp.MustCompile(`(?i)postgres`), regexp.MustCompile(`(?i)pgsql`)},
	"Cloudflare": {regexp.MustCompile(`(?i)cloudflare`), regexp.MustCompile(`(?i)__cfduid`)},
}

// DetectTechs identifies technologies from headers and page content.
func DetectTechs(rawURL string) models.TechResult {
	res := models.TechResult{URL: rawURL, Tecnologias: map[string]models.Tech{}}
	client := Client(10)
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header = BaseHeaders()
	resp, err := client.Do(req)
	if err != nil {
		return res
	}
	defer resp.Body.Close()
	body := readBody(resp)
	server := resp.Header.Get("Server")
	xpb := resp.Header.Get("X-Powered-By")
	headers := server + " " + xpb

	for tech, pats := range techPatterns {
		if matchAny(headers, pats) {
			res.Tecnologias[tech] = models.Tech{Fuente: "Headers", Evidencia: strings.TrimSpace(headers)}
			continue
		}
		if matchAny(body, pats) {
			res.Tecnologias[tech] = models.Tech{Fuente: "Contenido", Evidencia: pats[0].String()}
		}
	}
	res.Total = len(res.Tecnologias)
	return res
}

// safeGetBody fetches the body of a URL, returning "" on any failure.
func safeGetBody(rawURL string) string {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header = BaseHeaders()
	resp, err := Client(10).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return readBody(resp)
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
