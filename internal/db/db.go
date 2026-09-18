package db

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"agente-seguridad/internal/models"
)

// Store wraps the MySQL connection pool and exposes the data access methods
// used by the agent and the HTTP API.
type Store struct {
	DB *sql.DB
}

// Connect opens a MySQL connection using the given DSN components and pings it.
func Connect(host, port, user, password, name string) (*Store, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&loc=Local&multiStatements=true",
		user, password, host, port, name)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("ping mysql: %w", err)
	}
	return &Store{DB: db}, nil
}

// baseURL is not needed here; kept for API convenience in other packages.
const (
	stateInProgress = "en_proceso"
	stateCompleted  = "completado"
	stateError      = "error"
)

// EnsureSchema creates all tables if they do not exist.
func (s *Store) EnsureSchema() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS sitios (
			id INT AUTO_INCREMENT PRIMARY KEY,
			url VARCHAR(2048) NOT NULL UNIQUE,
			nombre VARCHAR(255),
			fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
			ultimo_escaneo DATETIME,
			activo BOOLEAN DEFAULT TRUE
		)`,
		`CREATE TABLE IF NOT EXISTS escaneos (
			id INT AUTO_INCREMENT PRIMARY KEY,
			sitio_id INT,
			fecha_inicio DATETIME DEFAULT CURRENT_TIMESTAMP,
			fecha_fin DATETIME,
			estado VARCHAR(32) DEFAULT 'en_proceso',
			total_vulnerabilidades INT DEFAULT 0,
			criticas INT DEFAULT 0,
			altas INT DEFAULT 0,
			medias INT DEFAULT 0,
			bajas INT DEFAULT 0,
			puertos_abiertos INT DEFAULT 0,
			directorios_encontrados INT DEFAULT 0,
			INDEX idx_sitio (sitio_id)
		)`,
		`CREATE TABLE IF NOT EXISTS vulnerabilidades (
			id INT AUTO_INCREMENT PRIMARY KEY,
			escaneo_id INT,
			tipo VARCHAR(255),
			severidad VARCHAR(32),
			parametro VARCHAR(512),
			payload TEXT,
			evidencia TEXT,
			url_afectada VARCHAR(2048),
			fecha_deteccion DATETIME DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_escaneo (escaneo_id)
		)`,
		`CREATE TABLE IF NOT EXISTS puertos (
			id INT AUTO_INCREMENT PRIMARY KEY,
			escaneo_id INT,
			puerto INT,
			servicio VARCHAR(128),
			estado VARCHAR(32),
			producto VARCHAR(255),
			version VARCHAR(128),
			INDEX idx_escaneo (escaneo_id)
		)`,
		`CREATE TABLE IF NOT EXISTS directorios (
			id INT AUTO_INCREMENT PRIMARY KEY,
			escaneo_id INT,
			directorio VARCHAR(2048),
			status_code INT,
			tamano INT,
			INDEX idx_escaneo (escaneo_id)
		)`,
		`CREATE TABLE IF NOT EXISTS cambios_sitios (
			id INT AUTO_INCREMENT PRIMARY KEY,
			sitio_id INT,
			escaneo_id INT,
			tipo_cambio VARCHAR(64),
			descripcion VARCHAR(1024),
			hash_anterior VARCHAR(64),
			hash_actual VARCHAR(64),
			fecha_deteccion DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS subdominios (
			id INT AUTO_INCREMENT PRIMARY KEY,
			sitio_id INT,
			subdominio VARCHAR(255),
			dominio_completo VARCHAR(255),
			existe BOOLEAN DEFAULT FALSE,
			ip VARCHAR(64),
			cname VARCHAR(255),
			servicio VARCHAR(128),
			takeover_posible BOOLEAN DEFAULT FALSE,
			http_status INT,
			fecha_deteccion DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE TABLE IF NOT EXISTS tecnologias (
			id INT AUTO_INCREMENT PRIMARY KEY,
			escaneo_id INT,
			tecnologia VARCHAR(128),
			fuente VARCHAR(64),
			evidencia VARCHAR(512),
			INDEX idx_escaneo (escaneo_id)
		)`,
		`CREATE TABLE IF NOT EXISTS logs_escaneo (
			id INT AUTO_INCREMENT PRIMARY KEY,
			escaneo_id INT,
			nivel VARCHAR(16),
			mensaje VARCHAR(2048),
			fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
			INDEX idx_escaneo (escaneo_id)
		)`,
		`CREATE TABLE IF NOT EXISTS codigo_fuente (
			id INT AUTO_INCREMENT PRIMARY KEY,
			escaneo_id INT,
			sitio_id INT,
			categoria VARCHAR(128),
			hallazgo VARCHAR(255),
			valor TEXT,
			fuente VARCHAR(512),
			severidad VARCHAR(32),
			hash VARCHAR(64),
			fecha_deteccion DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, st := range stmts {
		if _, err := s.DB.Exec(st); err != nil {
			return fmt.Errorf("schema init: %w", err)
		}
	}
	return nil
}

// ===================== SITIOS =====================

type Sitio struct {
	ID            int64      `json:"id"`
	URL           string     `json:"url"`
	Nombre        string     `json:"nombre"`
	FechaCreacion time.Time  `json:"fecha_creacion"`
	UltimoEscaneo *time.Time `json:"ultimo_escaneo"`
	Activo        bool       `json:"activo"`
}

func (s *Store) AgregarSitio(url, nombre string) (int64, error) {
	res, err := s.DB.Exec(`
		INSERT INTO sitios (url, nombre, fecha_creacion, activo)
		VALUES (?, ?, NOW(), TRUE)
		ON DUPLICATE KEY UPDATE activo = TRUE, nombre = COALESCE(?, nombre)`,
		url, nombre, nombre)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) SitiosActivos() ([]Sitio, error) {
	rows, err := s.DB.Query(`SELECT id, url, IFNULL(nombre,''), fecha_creacion, ultimo_escaneo, activo
		FROM sitios WHERE activo = TRUE ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sitios := []Sitio{}
	for rows.Next() {
		var st Sitio
		if err := rows.Scan(&st.ID, &st.URL, &st.Nombre, &st.FechaCreacion, &st.UltimoEscaneo, &st.Activo); err != nil {
			return nil, err
		}
		sitios = append(sitios, st)
	}
	return sitios, rows.Err()
}

func (s *Store) SitioPorID(id int64) (*Sitio, error) {
	row := s.DB.QueryRow(`SELECT id, url, IFNULL(nombre,''), fecha_creacion, ultimo_escaneo, activo
		FROM sitios WHERE id = ?`, id)
	var st Sitio
	if err := row.Scan(&st.ID, &st.URL, &st.Nombre, &st.FechaCreacion, &st.UltimoEscaneo, &st.Activo); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *Store) ActualizarUltimoEscaneo(id int64) error {
	_, err := s.DB.Exec(`UPDATE sitios SET ultimo_escaneo = NOW() WHERE id = ?`, id)
	return err
}

func (s *Store) DesactivarSitio(id int64) error {
	_, err := s.DB.Exec(`UPDATE sitios SET activo = FALSE WHERE id = ?`, id)
	return err
}

// ===================== ESCANEOS =====================

func (s *Store) IniciarEscaneo(sitioID int64) (int64, error) {
	res, err := s.DB.Exec(`INSERT INTO escaneos (sitio_id, fecha_inicio, estado) VALUES (?, NOW(), ?)`,
		sitioID, stateInProgress)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	s.AgregarLog(id, "INFO", fmt.Sprintf("Inicio de escaneo para sitio %d", sitioID))
	return id, nil
}

func (s *Store) FinalizarEscaneo(escaneoID int64, totalVulns, criticas, altas, medias, bajas, puertos, dirs int) error {
	_, err := s.DB.Exec(`
		UPDATE escaneos SET fecha_fin = NOW(), estado = ?,
			total_vulnerabilidades = ?, criticas = ?, altas = ?, medias = ?, bajas = ?,
			puertos_abiertos = ?, directorios_encontrados = ?
		WHERE id = ?`,
		stateCompleted, totalVulns, criticas, altas, medias, bajas, puertos, dirs, escaneoID)
	if err != nil {
		return err
	}
	s.AgregarLog(escaneoID, "INFO", "Escaneo completado exitosamente")
	return nil
}

func (s *Store) MarcarEscaneoError(escaneoID int64) error {
	_, err := s.DB.Exec(`UPDATE escaneos SET fecha_fin = NOW(), estado = ? WHERE id = ?`, stateError, escaneoID)
	if err != nil {
		return err
	}
	s.AgregarLog(escaneoID, "ERROR", "Error en escaneo")
	return nil
}

// ===================== VULNERABILIDADES =====================

func (s *Store) GuardarVulnerabilidades(escaneoID int64, vulns []models.Vulnerabilidad) error {
	if len(vulns) == 0 {
		return nil
	}
	for _, v := range vulns {
		_, err := s.DB.Exec(`
			INSERT INTO vulnerabilidades (escaneo_id, tipo, severidad, parametro, payload, evidencia, url_afectada, fecha_deteccion)
			VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
			escaneoID, v.Tipo, v.Severidad, v.Parametro, truncate(v.Payload, 1000), truncate(v.Evidencia, 1000), v.URL)
		if err != nil {
			return err
		}
	}
	s.AgregarLog(escaneoID, "INFO", fmt.Sprintf("Se guardaron %d vulnerabilidades", len(vulns)))
	return nil
}

func (s *Store) GuardarPuertos(escaneoID int64, servicios map[int]models.PortInfo) error {
	if len(servicios) == 0 {
		return nil
	}
	for puerto, p := range servicios {
		_, err := s.DB.Exec(`
			INSERT INTO puertos (escaneo_id, puerto, servicio, estado, producto, version)
			VALUES (?, ?, ?, ?, ?, ?)`,
			escaneoID, puerto, p.Servicio, p.Estado, p.Producto, p.Version)
		if err != nil {
			return err
		}
	}
	s.AgregarLog(escaneoID, "INFO", fmt.Sprintf("Se guardaron %d puertos", len(servicios)))
	return nil
}

func (s *Store) GuardarDirectorios(escaneoID int64, dirs []models.Directorio) error {
	if len(dirs) == 0 {
		return nil
	}
	for _, d := range dirs {
		_, err := s.DB.Exec(`
			INSERT INTO directorios (escaneo_id, directorio, status_code, tamano)
			VALUES (?, ?, ?, ?)`,
			escaneoID, d.URL, d.Status, d.Tamano)
		if err != nil {
			return err
		}
	}
	s.AgregarLog(escaneoID, "INFO", fmt.Sprintf("Se guardaron %d directorios", len(dirs)))
	return nil
}

func (s *Store) GuardarTecnologias(escaneoID int64, techs map[string]models.Tech) error {
	if len(techs) == 0 {
		return nil
	}
	for name, t := range techs {
		_, err := s.DB.Exec(`
			INSERT INTO tecnologias (escaneo_id, tecnologia, fuente, evidencia)
			VALUES (?, ?, ?, ?)`,
			escaneoID, name, t.Fuente, truncate(t.Evidencia, 200))
		if err != nil {
			return err
		}
	}
	s.AgregarLog(escaneoID, "INFO", fmt.Sprintf("Se guardaron %d tecnologias", len(techs)))
	return nil
}

func (s *Store) GuardarCambio(sitioID, escaneoID int64, tipo, desc, hashAnt, hashAct string) error {
	_, err := s.DB.Exec(`
		INSERT INTO cambios_sitios (sitio_id, escaneo_id, tipo_cambio, descripcion, hash_anterior, hash_actual, fecha_deteccion)
		VALUES (?, ?, ?, ?, ?, ?, NOW())`,
		sitioID, escaneoID, tipo, desc, nilString(hashAnt), nilString(hashAct))
	if err != nil {
		return err
	}
	s.AgregarLog(escaneoID, "INFO", fmt.Sprintf("Cambio detectado: %s", tipo))
	return nil
}

func (s *Store) GuardarSubdominios(sitioID int64, subs []models.Subdominio) error {
	if len(subs) == 0 {
		return nil
	}
	for _, sub := range subs {
		_, err := s.DB.Exec(`
			INSERT INTO subdominios (sitio_id, subdominio, dominio_completo, existe, ip, cname, servicio, takeover_posible, http_status, fecha_deteccion)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
			sitioID, sub.Subdominio, sub.DominioCompleto, sub.Existe, sub.IP, nilString(sub.CNAME), sub.Servicio,
			sub.TakeoverPosible, sub.HTTPStatus)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GuardarCodigoFuente(escaneoID, sitioID int64, hallazgos []models.Hallazgo) error {
	if len(hallazgos) == 0 {
		return nil
	}
	for _, h := range hallazgos {
		_, err := s.DB.Exec(`
			INSERT INTO codigo_fuente (escaneo_id, sitio_id, categoria, hallazgo, valor, fuente, severidad, hash, fecha_deteccion)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
			escaneoID, sitioID, truncate(h.Categoria, 100), truncate(h.Descripcion, 100),
			truncate(h.Valor, 500), truncate(h.Fuente, 200), h.Severidad, h.Hash)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) AgregarLog(escaneoID int64, nivel, msg string) error {
	_, err := s.DB.Exec(`INSERT INTO logs_escaneo (escaneo_id, nivel, mensaje, fecha) VALUES (?, ?, ?, NOW())`,
		escaneoID, nivel, truncate(msg, 500))
	if err != nil {
		log.Printf("log error: %v", err)
	}
	return err
}

// ===================== ESTADISTICAS =====================

type Estadisticas struct {
	TotalSitios               int              `json:"total_sitios"`
	TotalEscaneos             int              `json:"total_escaneos"`
	TotalVulnerabilidades     int              `json:"total_vulnerabilidades"`
	PorSeveridad              map[string]int   `json:"por_severidad"`
	GraficoDiario             []DiaGrafico     `json:"grafico_diario"`
	UltimosEscaneos           []EscaneoDetalle `json:"ultimos_escaneos"`
	CambiosRecientes          []CambioDetalle  `json:"cambios_recientes"`
	Sitios                    []SitioGlobal    `json:"sitios"`
	VulnerabilidadesRecientes []VulnDetalle    `json:"vulnerabilidades_recientes"`
}

type DiaGrafico struct {
	Fecha         string `json:"fecha"`
	TotalEscaneos int    `json:"total_escaneos"`
	Criticas      int    `json:"criticas"`
	Altas         int    `json:"altas"`
	Medias        int    `json:"medias"`
}

type EscaneoDetalle struct {
	ID                     int64   `json:"id"`
	FechaInicio            string  `json:"fecha_inicio"`
	FechaFin               *string `json:"fecha_fin"`
	Estado                 string  `json:"estado"`
	TotalVulnerabilidades  int     `json:"total_vulnerabilidades"`
	Criticas               int     `json:"criticas"`
	Altas                  int     `json:"altas"`
	Medias                 int     `json:"medias"`
	PuertosAbiertos        int     `json:"puertos_abiertos"`
	DirectoriosEncontrados int     `json:"directorios_encontrados"`
	URL                    string  `json:"url"`
	Nombre                 string  `json:"nombre"`
}

type CambioDetalle struct {
	ID          int64  `json:"id"`
	TipoCambio  string `json:"tipo_cambio"`
	Descripcion string `json:"descripcion"`
	Fecha       string `json:"fecha_deteccion"`
	URL         string `json:"url"`
	Nombre      string `json:"nombre"`
}

type SitioGlobal struct {
	ID            int64   `json:"id"`
	URL           string  `json:"url"`
	Nombre        string  `json:"nombre"`
	FechaCreacion string  `json:"fecha_creacion"`
	UltimoEscaneo *string `json:"ultimo_escaneo"`
	TotalEscaneos int     `json:"total_escaneos"`
	TotalVulns    int     `json:"total_vulns"`
}

type VulnDetalle struct {
	ID        int64  `json:"id"`
	Tipo      string `json:"tipo"`
	Severidad string `json:"severidad"`
	Parametro string `json:"parametro"`
	Payload   string `json:"payload"`
	Evidencia string `json:"evidencia"`
	Fecha     string `json:"fecha_deteccion"`
	URL       string `json:"url"`
	Nombre    string `json:"nombre"`
}

func (s *Store) EstadisticasGenerales() (*Estadisticas, error) {
	stats := &Estadisticas{PorSeveridad: map[string]int{}}

	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM sitios WHERE activo = TRUE`).Scan(&stats.TotalSitios)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM escaneos`).Scan(&stats.TotalEscaneos)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM vulnerabilidades`).Scan(&stats.TotalVulnerabilidades)

	// Severity breakdown
	rows, err := s.DB.Query(`SELECT severidad, COUNT(*) as total FROM vulnerabilidades GROUP BY severidad`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var total int
			if rows.Scan(&sev, &total) == nil {
				stats.PorSeveridad[sev] = total
			}
		}
	}

	// Daily graph (last 30 days)
	rows, err = s.DB.Query(`
		SELECT DATE(fecha_inicio) as fecha, COUNT(*) as escaneos,
			IFNULL(SUM(criticas),0) as criticas, IFNULL(SUM(altas),0) as altas, IFNULL(SUM(medias),0) as medias
		FROM escaneos WHERE fecha_inicio >= DATE_SUB(NOW(), INTERVAL 30 DAY)
		GROUP BY DATE(fecha_inicio) ORDER BY fecha ASC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var d DiaGrafico
			var fecha time.Time
			if rows.Scan(&fecha, &d.TotalEscaneos, &d.Criticas, &d.Altas, &d.Medias) == nil {
				d.Fecha = fecha.Format("2006-01-02")
				stats.GraficoDiario = append(stats.GraficoDiario, d)
			}
		}
	}

	// Recent scans
	rows, err = s.DB.Query(`
		SELECT e.id, e.fecha_inicio, e.fecha_fin, e.estado, e.total_vulnerabilidades,
			e.criticas, e.altas, e.medias, e.puertos_abiertos, e.directorios_encontrados, s.url, IFNULL(s.nombre,'')
		FROM escaneos e JOIN sitios s ON e.sitio_id = s.id
		ORDER BY e.fecha_inicio DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var e EscaneoDetalle
			if rows.Scan(&e.ID, &e.FechaInicio, &e.FechaFin, &e.Estado, &e.TotalVulnerabilidades,
				&e.Criticas, &e.Altas, &e.Medias, &e.PuertosAbiertos, &e.DirectoriosEncontrados, &e.URL, &e.Nombre) == nil {
				stats.UltimosEscaneos = append(stats.UltimosEscaneos, e)
			}
		}
	}

	// Recent changes
	rows, err = s.DB.Query(`
		SELECT c.id, c.tipo_cambio, c.descripcion, c.fecha_deteccion, s.url, IFNULL(s.nombre,'')
		FROM cambios_sitios c JOIN sitios s ON c.sitio_id = s.id
		ORDER BY c.fecha_deteccion DESC LIMIT 10`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c CambioDetalle
			if rows.Scan(&c.ID, &c.TipoCambio, &c.Descripcion, &c.Fecha, &c.URL, &c.Nombre) == nil {
				stats.CambiosRecientes = append(stats.CambiosRecientes, c)
			}
		}
	}

	// Active sites (with scan counts)
	rows, err = s.DB.Query(`
		SELECT s.id, s.url, IFNULL(s.nombre,''), s.fecha_creacion, s.ultimo_escaneo,
			(SELECT COUNT(*) FROM escaneos WHERE sitio_id = s.id) as escaneos,
			(SELECT COUNT(*) FROM vulnerabilidades v JOIN escaneos e ON v.escaneo_id = e.id WHERE e.sitio_id = s.id) as vulns
		FROM sitios s WHERE s.activo = TRUE ORDER BY s.fecha_creacion DESC`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sg SitioGlobal
			if rows.Scan(&sg.ID, &sg.URL, &sg.Nombre, &sg.FechaCreacion, &sg.UltimoEscaneo,
				&sg.TotalEscaneos, &sg.TotalVulns) == nil {
				stats.Sitios = append(stats.Sitios, sg)
			}
		}
	}

	// Recent vulnerabilities
	rows, err = s.DB.Query(`
		SELECT v.id, v.tipo, v.severidad, v.parametro, v.payload, v.evidencia, v.fecha_deteccion, s.url, IFNULL(s.nombre,'')
		FROM vulnerabilidades v JOIN escaneos e ON v.escaneo_id = e.id JOIN sitios s ON e.sitio_id = s.id
		ORDER BY v.fecha_deteccion DESC LIMIT 20`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var v VulnDetalle
			if rows.Scan(&v.ID, &v.Tipo, &v.Severidad, &v.Parametro, &v.Payload, &v.Evidencia, &v.Fecha, &v.URL, &v.Nombre) == nil {
				stats.VulnerabilidadesRecientes = append(stats.VulnerabilidadesRecientes, v)
			}
		}
	}

	return stats, nil
}

// SitioDetalle gathers detailed info for the dashboard "site" view.
func (s *Store) SitioDetalle(id int64) map[string]interface{} {
	sitio, err := s.SitioPorID(id)
	if err != nil {
		return nil
	}

	out := map[string]interface{}{"sitio": sitio}
	totalEscaneos, totalVulns := 0, 0
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM escaneos WHERE sitio_id = ?`, id).Scan(&totalEscaneos)
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM vulnerabilidades v JOIN escaneos e ON v.escaneo_id = e.id WHERE e.sitio_id = ?`, id).Scan(&totalVulns)
	out["total_escaneos"] = totalEscaneos
	out["total_vulns"] = totalVulns

	rows, _ := s.DB.Query(`SELECT id, fecha_inicio, fecha_fin, estado, total_vulnerabilidades,
		criticas, altas, medias, bajas, puertos_abiertos, directorios_encontrados
		FROM escaneos WHERE sitio_id = ? ORDER BY fecha_inicio DESC LIMIT 10`, id)
	defer rows.Close()
	var escaneos []map[string]interface{}
	for rows.Next() {
		var eid int64
		var fi string
		var ff *string
		var estadoBuf string
		var tv, cr, al, me, ba, pu, di int
		if err := rows.Scan(&eid, &fi, &ff, &estadoBuf, &tv, &cr, &al, &me, &ba, &pu, &di); err != nil {
			continue
		}
		escaneos = append(escaneos, map[string]interface{}{
			"id": eid, "fecha_inicio": fi, "fecha_fin": ff, "estado": estadoBuf,
			"total_vulnerabilidades": tv, "criticas": cr, "altas": al, "medias": me,
			"bajas": ba, "puertos_abiertos": pu, "directorios_encontrados": di,
		})
	}
	out["escaneos"] = escaneos

	rows, _ = s.DB.Query(`SELECT v.*, e.fecha_inicio FROM vulnerabilidades v
		JOIN escaneos e ON v.escaneo_id = e.id WHERE e.sitio_id = ?
		ORDER BY v.fecha_deteccion DESC LIMIT 50`, id)
	defer rows.Close()
	var vulns []map[string]interface{}
	for rows.Next() {
		cols, _ := rows.Columns()
		ptrs := make([]interface{}, len(cols))
		vals := make([]interface{}, len(cols))
		for i := range ptrs {
			ptrs[i] = &vals[i]
		}
		if rows.Scan(ptrs...) == nil {
			m := map[string]interface{}{}
			for i, c := range cols {
				m[c] = vals[i]
			}
			vulns = append(vulns, m)
		}
	}
	out["vulnerabilidades"] = vulns

	rows, _ = s.DB.Query(`SELECT * FROM tecnologias t JOIN escaneos e ON t.escaneo_id = e.id
		WHERE e.sitio_id = ? ORDER BY e.fecha_inicio DESC LIMIT 20`, id)
	defer rows.Close()
	var techs []map[string]interface{}
	for rows.Next() {
		cols, _ := rows.Columns()
		ptrs := make([]interface{}, len(cols))
		vals := make([]interface{}, len(cols))
		for i := range ptrs {
			ptrs[i] = &vals[i]
		}
		if rows.Scan(ptrs...) == nil {
			m := map[string]interface{}{}
			for i, c := range cols {
				m[c] = vals[i]
			}
			techs = append(techs, m)
		}
	}
	out["tecnologias"] = techs

	return out
}

// ===================== HELPERS =====================
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func nilString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
