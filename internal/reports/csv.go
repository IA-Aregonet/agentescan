package reports

import (
	"encoding/csv"
	"fmt"
	"os"
	"time"

	"agente-seguridad/internal/db"
)

// Generator writes CSV reports derived from stored scan data.
type Generator struct {
	baseDir string
	store   *db.Store
}

// New builds a Generator writing to baseDir, backed by store.
func New(store *db.Store, baseDir string) *Generator {
	_ = os.MkdirAll(baseDir, 0o755)
	return &Generator{baseDir: baseDir, store: store}
}

// GenerateCSV produces a CSV of vulnerabilities for a site and returns its path,
// or "" if there is nothing to export.
func (g *Generator) GenerateCSV(sitioID int64) string {
	rows, err := g.store.DB.Query(`
		SELECT v.fecha_deteccion, s.url, IFNULL(s.nombre,''), v.tipo, v.severidad,
			v.parametro, v.payload, v.evidencia, v.url_afectada
		FROM vulnerabilidades v
		JOIN escaneos e ON v.escaneo_id = e.id
		JOIN sitios s ON e.sitio_id = s.id
		WHERE s.id = ?
		ORDER BY v.fecha_deteccion DESC`, sitioID)
	if err != nil {
		return ""
	}
	defer rows.Close()

	return g.writeCSV("vulnerabilidades", []string{
		"Fecha", "Sitio", "Nombre_Sitio", "Tipo_Vulnerabilidad", "Severidad",
		"Parametro", "Payload", "Evidencia", "URL_Afectada",
	}, rows)
}

// writeCSV streams query rows into a CSV file, returning its path.
func (g *Generator) writeCSV(base string, header []string, rows interface {
	Next() bool
	Scan(...interface{}) error
}) string {
	type record []interface{}
	var data []record

	// Column count equals header length; scan into a generic slice.
	for rows.Next() {
		vals := make([]interface{}, len(header))
		ptrs := make([]interface{}, len(header))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return ""
		}
		data = append(data, vals)
	}
	if len(data) == 0 {
		return ""
	}

	fname := fmt.Sprintf("%s_%s.csv", base, time.Now().Format("20060102_150405"))
	path := g.baseDir + "/" + fname
	f, err := os.Create(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	w := csv.NewWriter(f)
	_ = w.Write(header)
	for _, rec := range data {
		strs := make([]string, len(rec))
		for i, v := range rec {
			if v == nil {
				strs[i] = ""
				continue
			}
			strs[i] = fmt.Sprint(v)
		}
		_ = w.Write(strs)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return ""
	}
	return path
}
