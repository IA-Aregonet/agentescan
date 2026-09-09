package agent

import (
	"fmt"
	"strings"
	"time"

	"agente-seguridad/internal/models"
)

// BuildReport renders a human-readable Telegram HTML report from results.
func BuildReport(nombre, rawURL string, res *models.Resultado) string {
	var b strings.Builder
	b.WriteString("🔐 <b>REPORTE DE ESCANEO - " + titleOrURL(nombre, rawURL) + "</b>\n")
	b.WriteString("📅 " + time.Now().Format("02/01/2006 15:04:05") + "\n")
	b.WriteString("═══════════════════════════\n\n")

	v := res.Vulnerabilidades
	b.WriteString("📊 <b>RESUMEN GENERAL</b>\n")
	b.WriteString("🌐 URL: " + rawURL + "\n")
	b.WriteString("🔍 Vulnerabilidades totales: " + itoa(v.Total) + "\n")
	b.WriteString("   🔴 Críticas: " + itoa(v.Criticas) + "\n")
	b.WriteString("   🟠 Altas: " + itoa(v.Altas) + "\n")
	b.WriteString("   🟡 Medias: " + itoa(v.Medias) + "\n")
	b.WriteString("🔌 Puertos abiertos: " + itoa(res.Puertos.TotalAbiertos) + "\n")
	b.WriteString("📁 Directorios encontrados: " + itoa(res.Directorios.TotalEncontrados) + "\n")
	b.WriteString("💻 Tecnologías detectadas: " + itoa(len(res.Tecnologias.Tecnologias)) + "\n")

	// Ports
	b.WriteString("\n🔌 <b>PUERTOS ABIERTOS ENCONTRADOS</b>\n")
	if len(res.Puertos.PuertosAbiertos) > 0 {
		for _, p := range res.Puertos.PuertosAbiertos {
			info := res.Puertos.Servicios[p]
			b.WriteString(fmt.Sprintf("   🔹 Puerto %d: %s\n", p, info.Servicio))
		}
	} else {
		b.WriteString("   No se encontraron puertos abiertos\n")
	}

	// Directories
	b.WriteString("\n📁 <b>DIRECTORIOS ENCONTRADOS</b>\n")
	if len(res.Directorios.DirectoriosEncontrados) > 0 {
		n := len(res.Directorios.DirectoriosEncontrados)
		if n > 20 {
			n = 20
		}
		for i, d := range res.Directorios.DirectoriosEncontrados[:n] {
			b.WriteString(fmt.Sprintf("   %d. [%d] %s\n", i+1, d.Status, d.URL))
		}
		if len(res.Directorios.DirectoriosEncontrados) > 20 {
			b.WriteString("... y más. El CSV contiene el listado completo.\n")
		}
	} else {
		b.WriteString("   No se encontraron directorios ocultos\n")
	}

	// Subdomains
	if res.Subdomains.TotalSubdominiosEncontrados > 0 {
		b.WriteString("\n🌐 <b>SUBDOMINIOS ENCONTRADOS</b>\n")
		for _, s := range res.Subdomains.SubdominiosAnalizados {
			if s.Existe {
				b.WriteString(fmt.Sprintf("   🔹 %s (%s)\n", s.DominioCompleto, s.IP))
			}
		}
	}

	// Subdomain takeover
	if res.Subdomains.TotalTakeovers > 0 {
		b.WriteString("\n⚠️ <b>SUBDOMINIOS CON POSIBLE TAKEOVER</b>\n")
		for _, s := range res.Subdomains.SubdominiosAnalizados {
			if s.TakeoverPosible {
				b.WriteString(fmt.Sprintf("   🔴 %s -> %s\n", s.DominioCompleto, s.Servicio))
			}
		}
	}

	// Changes
	if res.Cambios != nil && res.Cambios.Cambio {
		b.WriteString("\n🔄 <b>CAMBIO DETECTADO</b>\n")
		b.WriteString(res.Cambios.Mensaje + "\n")
	}

	// Vulnerabilities
	if len(v.Vulnerabilidades) > 0 {
		b.WriteString("\n🚨 <b>VULNERABILIDADES ENCONTRADAS (" + itoa(len(v.Vulnerabilidades)) + ")</b>\n")
		n := len(v.Vulnerabilidades)
		if n > 10 {
			n = 10
		}
		for i, vuln := range v.Vulnerabilidades[:n] {
			b.WriteString(fmt.Sprintf("%s <b>#%d</b> %s\n", emoji(vuln.Severidad), i+1, vuln.Tipo))
			b.WriteString("   Severidad: " + vuln.Severidad + "\n")
			b.WriteString("   Parámetro: " + vuln.Parametro + "\n")
			b.WriteString("   Payload: " + truncateAt(vuln.Payload, 50) + "\n")
		}
		if len(v.Vulnerabilidades) > 10 {
			b.WriteString("... y " + itoa(len(v.Vulnerabilidades)-10) + " más. El CSV contiene el listado completo.\n")
		}
	}

	// Source code findings
	if res.CodigoFuente.Total > 0 {
		b.WriteString("\n🔍 <b>ANÁLISIS DE CÓDIGO FUENTE</b>\n")
		b.WriteString("📊 Hallazgos: " + itoa(res.CodigoFuente.Total) + "\n")
		b.WriteString("📁 Archivos analizados: " + itoa(res.CodigoFuente.ArchivosAnalizados) + "\n")
	}

	b.WriteString("\n═══════════════════════════\n")
	b.WriteString("📊 Dashboard: http://localhost:8080/\n")
	return b.String()
}

func emoji(sev string) string {
	switch sev {
	case "Crítica":
		return "🔴"
	case "Alta":
		return "🟠"
	case "Media":
		return "🟡"
	case "Baja":
		return "🟢"
	}
	return "⚪"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	return fmt.Sprint(n)
}

func truncateAt(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	if s == "" {
		return "N/A"
	}
	return s
}
