package agent

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"

	"agente-seguridad/internal/config"
	"agente-seguridad/internal/db"
	"agente-seguridad/internal/models"
	"agente-seguridad/internal/notifier"
	"agente-seguridad/internal/reports"
	"agente-seguridad/internal/scanner"
)

// Agent orchestrates full-site security scans.
type Agent struct {
	cfg     config.Config
	store   *db.Store
	notes   *notifier.Notifier
	report  *reports.Generator
	monitor *scanner.ChangeMonitor
	words   []string
}

// New builds an Agent using the given store and notifier. It loads fuzzing and
// monitoring state from disk.
func New(cfg config.Config, store *db.Store, notes *notifier.Notifier, rep *reports.Generator) *Agent {
	return &Agent{
		cfg:     cfg,
		store:   store,
		notes:   notes,
		report:  rep,
		monitor: scanner.NewChangeMonitor(cfg.ReportsDir),
		words:   scanner.LoadWordlist(cfg.WordlistPath),
	}
}

// RunScan executes a single concurrent scan for a site and persists results.
func (a *Agent) RunScan(sitioID int64) error {
	sitio, err := a.store.SitioPorID(sitioID)
	if err != nil {
		return fmt.Errorf("sitio %d no encontrado: %w", sitioID, err)
	}
	rawURL := scanner.EnsureScheme(sitio.URL)

	escaneoID, err := a.store.IniciarEscaneo(sitioID)
	if err != nil {
		return err
	}

	log.Printf("🔍 INICIANDO ESCANEO PARA: %s", rawURL)
	a.store.AgregarLog(escaneoID, "INFO", "Escaneando puertos...")
	a.store.AgregarLog(escaneoID, "INFO", "Fuzzing de directorios...")
	a.store.AgregarLog(escaneoID, "INFO", "Detectando vulnerabilidades...")
	a.store.AgregarLog(escaneoID, "INFO", "Detectando tecnologías, análisis web y código fuente...")

	res, err := a.scanSiteConcurrent(rawURL)
	if err != nil {
		a.store.MarcarEscaneoError(escaneoID)
		return err
	}

	// ---- Persist ----
	a.persist(sitioID, escaneoID, res)
	if err := a.store.FinalizarEscaneo(escaneoID,
		res.Vulnerabilidades.Total, res.Vulnerabilidades.Criticas, res.Vulnerabilidades.Altas,
		res.Vulnerabilidades.Medias, res.Vulnerabilidades.Bajas,
		res.Puertos.TotalAbiertos, res.Directorios.TotalEncontrados); err != nil {
		return err
	}
	a.store.ActualizarUltimoEscaneo(sitioID)
	log.Printf("✅ Escaneo completado! ID: %d", escaneoID)

	// ---- Notify ----
	a.notify(sitioID, rawURL, res, escaneoID)
	return nil
}

// scanSiteConcurrent runs the top-level detectors in parallel with an
// errgroup, coalescing partial results.
func (a *Agent) scanSiteConcurrent(rawURL string) (*models.Resultado, error) {
	res := &models.Resultado{
		URL: rawURL, Timestamp: time.Now().Format(time.RFC3339),
		Puertos:      models.PortScanResult{Servicios: map[int]models.PortInfo{}},
		Tecnologias:  models.TechResult{Tecnologias: map[string]models.Tech{}},
		CodigoFuente: models.SourceResult{Encontrados: map[string][]models.Hallazgo{}},
	}

	domain := scanner.DomainFromURL(rawURL)
	g := &errgroup.Group{}
	g.Go(func() error {
		res.Puertos = scanner.ScanPorts(rawURL, a.cfg.MaxWorkers)
		return nil
	})
	g.Go(func() error {
		res.Directorios = scanner.FuzzDirectorios(rawURL, a.words, a.cfg.MaxWorkers)
		return nil
	})
	g.Go(func() error {
		res.Vulnerabilidades = scanner.AnalyzeVulnerabilities(rawURL, a.cfg.MaxWorkers)
		return nil
	})
	g.Go(func() error {
		c := a.monitor.Check(rawURL)
		res.Cambios = &c
		return nil
	})
	g.Go(func() error {
		res.Tecnologias = scanner.DetectTechs(rawURL)
		return nil
	})
	g.Go(func() error {
		res.CSRF = scanner.AnalyzeCSRF(rawURL)
		return nil
	})
	g.Go(func() error {
		res.GraphQL = scanner.AnalyzeGraphQL(rawURL)
		return nil
	})
	g.Go(func() error {
		res.WebSocket = scanner.AnalyzeWebSocket(rawURL)
		return nil
	})
	g.Go(func() error {
		res.RaceConditions = scanner.AnalyzeRaceConditions(rawURL)
		return nil
	})
	g.Go(func() error {
		res.CachePoisoning = scanner.AnalyzeCachePoisoning(rawURL)
		return nil
	})
	g.Go(func() error {
		if domain != "" && strings.Contains(domain, ".") {
			res.Subdomains = scanner.ScanSubdomains(domain, 30)
		}
		return nil
	})
	g.Go(func() error {
		res.CORS = scanner.AnalyzeCORS(rawURL)
		return nil
	})
	g.Go(func() error {
		res.CodigoFuente = scanner.AnalyzeSourceCode(rawURL, 10)
		return nil
	})

	if err := g.Wait(); err != nil {
		return res, err
	}
	return res, nil
}

// persist writes a Resultado into the database.
func (a *Agent) persist(sitioID, escaneoID int64, res *models.Resultado) {
	a.store.GuardarVulnerabilidades(escaneoID, res.Vulnerabilidades.Vulnerabilidades)
	a.store.GuardarPuertos(escaneoID, res.Puertos.Servicios)
	a.store.GuardarDirectorios(escaneoID, res.Directorios.DirectoriosEncontrados)
	a.store.GuardarTecnologias(escaneoID, res.Tecnologias.Tecnologias)

	if res.Cambios != nil && res.Cambios.Cambio {
		a.store.GuardarCambio(sitioID, escaneoID, "contenido", res.Cambios.Mensaje,
			res.Cambios.HashAnterior, res.Cambios.HashActual)
	}

	if len(res.Subdomains.SubdominiosAnalizados) > 0 {
		a.store.GuardarSubdominios(sitioID, res.Subdomains.SubdominiosAnalizados)
	}

	var hallazgos []models.Hallazgo
	for _, items := range res.CodigoFuente.Encontrados {
		hallazgos = append(hallazgos, items...)
	}
	if len(hallazgos) > 0 {
		a.store.GuardarCodigoFuente(escaneoID, sitioID, hallazgos)
	}
}

// notify builds and sends the Telegram report + CSV attachments (if configured).
func (a *Agent) notify(sitioID int64, rawURL string, res *models.Resultado, escaneoID int64) {
	if a.notes == nil {
		return
	}
	sitio, _ := a.store.SitioPorID(sitioID)
	nombre := ""
	if sitio != nil {
		nombre = sitio.Nombre
	}
	msg := BuildReport(nombre, rawURL, res)

	a.notes.SendText(msg)
	if rep := a.report.GenerateCSV(sitioID); rep != "" {
		a.notes.SendFile(rep, "📊 Vulnerabilidades de "+titleOrURL(nombre, rawURL))
	}
}

func titleOrURL(nombre, rawURL string) string {
	if nombre != "" {
		return nombre
	}
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	return rawURL
}
