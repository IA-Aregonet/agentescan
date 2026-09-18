package scanner

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"agente-seguridad/internal/models"
)

func detectXSS(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, xssPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		client := Client(5)
		_, body := getWithParams(client, u, p, payload, false)
		if strings.Contains(body, payload) || strings.Contains(body, strings.ReplaceAll(payload, "<", "&lt;")) {
			return models.Vulnerabilidad{
				Tipo: "XSS (Reflejado)", Parametro: p, Payload: payload,
				Evidencia: "Payload reflejado en respuesta", Severidad: "Alta", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectSQLi(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, sqlPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		client := Client(10)
		start := time.Now()
		_, body := getWithParams(client, u, p, payload, false)
		elapsed := time.Since(start).Seconds()
		if matchAny(body, reSQL) {
			return models.Vulnerabilidad{
				Tipo: "SQL Injection (Error-based)", Parametro: p, Payload: payload,
				Evidencia: "Error SQL detectado", Severidad: "Crítica", URL: u,
			}, true
		}
		if (strings.Contains(payload, "SLEEP") || strings.Contains(payload, "WAITFOR")) && elapsed > 4 {
			return models.Vulnerabilidad{
				Tipo: "SQL Injection (Time-based)", Parametro: p, Payload: payload,
				Evidencia: "Respuesta tardó " + truncFloat(elapsed) + "s", Severidad: "Alta", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectPath(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, pathPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		_, body := getWithParams(Client(5), u, p, payload, false)
		if matchAny(body, rePath) {
			return models.Vulnerabilidad{
				Tipo: "Path Traversal", Parametro: p, Payload: payload,
				Evidencia: "Archivo del sistema detectado", Severidad: "Alta", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectSSTI(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, sstiPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		_, body := getWithParams(Client(5), u, p, payload, false)
		if strings.Contains(body, "49") && strings.Contains(payload, "7*7") {
			return models.Vulnerabilidad{
				Tipo: "SSTI (Server-Side Template Injection)", Parametro: p, Payload: payload,
				Evidencia: "Cálculo 7*7 = 49 ejecutado", Severidad: "Crítica", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectLFI(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, lfiPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		_, body := getWithParams(Client(5), u, p, payload, false)
		if strings.Contains(body, "root:x:") || strings.Contains(body, "DB_PASSWORD") {
			return models.Vulnerabilidad{
				Tipo: "LFI (Local File Inclusion)", Parametro: p, Payload: payload,
				Evidencia: "Contenido de archivo expuesto", Severidad: "Crítica", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectCmd(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, cmdPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		_, body := getWithParams(Client(5), u, p, payload, false)
		if matchAny(body, reCmd) {
			return models.Vulnerabilidad{
				Tipo: "Command Injection", Parametro: p, Payload: payload,
				Evidencia: "Salida de comando detectada", Severidad: "Crítica", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectCRLF(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, crlfPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		resp, _ := getWithParams(Client(5), u, p, payload, false)
		if resp != nil && strings.Contains(resp.Header.Get("Set-Cookie"), "hacked=1") {
			return models.Vulnerabilidad{
				Tipo: "CRLF Injection", Parametro: p, Payload: payload,
				Evidencia: "Cabecera HTTP inyectada", Severidad: "Media", URL: u,
			}, true
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectRedirect(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	return sweepParams(rawURL, params, redirPayloads, workers, func(u, p, payload string) (models.Vulnerabilidad, bool) {
		resp, _ := getWithParams(Client(5), u, p, payload, true)
		if resp == nil {
			return models.Vulnerabilidad{}, false
		}
		if resp.StatusCode >= 301 && resp.StatusCode <= 308 {
			loc := resp.Header.Get("Location")
			if strings.Contains(loc, "evil.com") || strings.Contains(loc, "://") {
				return models.Vulnerabilidad{
					Tipo: "Open Redirect", Parametro: p, Payload: payload,
					Evidencia: "Redirección a: " + loc, Severidad: "Media", URL: u,
				}, true
			}
		}
		return models.Vulnerabilidad{}, false
	})
}

func detectXXE(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	var out []models.Vulnerabilidad
	for param := range params {
		if !strings.Contains(strings.ToLower(param), "xml") {
			continue
		}
		for _, payload := range xxePayloads {
			_, body := getWithParams(Client(5), rawURL, param, payload, false)
			if strings.Contains(body, "root:x:") {
				v := models.Vulnerabilidad{
					Tipo: "XXE (XML External Entity)", Parametro: param,
					Payload:   truncateStr(payload, 50) + "...",
					Evidencia: "Contenido de archivo expuesto", Severidad: "Crítica", URL: rawURL,
				}
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func detectSSRF(rawURL string, params map[string]string, workers int) []models.Vulnerabilidad {
	var out []models.Vulnerabilidad
	for param := range params {
		lp := strings.ToLower(param)
		if !strings.Contains(lp, "url") && !strings.Contains(lp, "path") {
			continue
		}
		for _, payload := range ssrfPayloads {
			_, body := getWithParams(Client(5), rawURL, param, payload, false)
			if strings.Contains(body, "ami-id") || strings.Contains(body, "instance-id") {
				v := models.Vulnerabilidad{
					Tipo: "SSRF (Server-Side Request Forgery)", Parametro: param, Payload: payload,
					Evidencia: "Metadata de cloud expuesta", Severidad: "Crítica", URL: rawURL,
				}
				out = append(out, v)
				break
			}
		}
	}
	return out
}

func detectSecurityHeaders(rawURL string) []models.Vulnerabilidad {
	var out []models.Vulnerabilidad
	client := Client(5)
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return out
	}
	req.Header = BaseHeaders()
	resp, err := client.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()
	checks := map[string]string{
		"Strict-Transport-Security": "HSTS no implementado",
		"Content-Security-Policy":   "CSP no implementado",
		"X-Frame-Options":           "Clickjacking permitido",
		"X-Content-Type-Options":    "MIME sniffing permitido",
	}
	for h, msg := range checks {
		if resp.Header.Get(h) == "" {
			out = append(out, models.Vulnerabilidad{
				Tipo: "Missing Security Header", Parametro: h, Payload: "N/A",
				Evidencia: msg, Severidad: "Media", URL: rawURL,
			})
		}
	}
	return out
}

func truncFloat(f float64) string {
	return strings.TrimSuffix(strings.TrimSuffix(fmt.Sprintf("%.2f", f), "0"), ".")
}
