package httpapi

import (
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"agente-seguridad/internal/agent"
	"agente-seguridad/internal/db"
)

// Handler serves the embedded dashboard plus the JSON API.
type Handler struct {
	store *db.Store
	agent *agent.Agent
	web   fs.FS
}

// New builds the HTTP handler. It embeds the dashboard and wires REST endpoints.
func New(store *db.Store, ag *agent.Agent, webFS fs.FS) http.Handler {
	h := &Handler{store: store, agent: ag, web: webFS}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/estadisticas", h.estadisticas)
	mux.HandleFunc("/api/sitio", h.sitio)
	mux.HandleFunc("/api/sitios", h.addSitio)
	mux.HandleFunc("/api/scan", h.scan)
	mux.HandleFunc("/severidad_chart", h.severidadChart)

	fileServer := http.FileServer(http.FS(webFS))
	mux.Handle("/", fileServer)
	return logRequests(mux)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *Handler) estadisticas(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.EstadisticasGenerales()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, stats)
}

func (h *Handler) sitio(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("id")
	if raw == "" {
		writeJSON(w, 400, map[string]string{"error": "ID de sitio requerido"})
		return
	}
	id, _ := strconv.ParseInt(raw, 10, 64)
	data := h.store.SitioDetalle(id)
	if data == nil {
		writeJSON(w, 404, map[string]string{"error": "Sitio no encontrado"})
		return
	}
	writeJSON(w, 200, data)
}

func (h *Handler) addSitio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST requerido"})
		return
	}
	var req struct {
		URL    string `json:"url"`
		Nombre string `json:"nombre"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "cuerpo inválido"})
		return
	}
	if req.URL == "" {
		writeJSON(w, 400, map[string]string{"error": "url requerida"})
		return
	}
	id, err := h.store.AgregarSitio(req.URL, req.Nombre)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 201, map[string]interface{}{"id": id})
}

// scan triggers an immediate asynchronous scan for a site.
func (h *Handler) scan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "POST requerido"})
		return
	}
	var req struct {
		SitioID int64 `json:"sitio_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "cuerpo inválido"})
		return
	}
	if req.SitioID <= 0 {
		writeJSON(w, 400, map[string]string{"error": "sitio_id requerido"})
		return
	}
	go func() {
		if err := h.agent.RunScan(req.SitioID); err != nil {
			log.Printf("scan %d errored: %v", req.SitioID, err)
		}
	}()
	writeJSON(w, 202, map[string]string{"status": "aceptado", "sitio_id": strconv.FormatInt(req.SitioID, 10)})
}

// severidadChart renders the doughnut severity chart (replaces the PHP iframe).
func (h *Handler) severidadChart(w http.ResponseWriter, r *http.Request) {
	stats, err := h.store.EstadisticasGenerales()
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	sev := map[string]int{}
	for k, v := range stats.PorSeveridad {
		sev[k] = v
	}
	if len(sev) == 0 {
		sev = map[string]int{"Sin datos": 0}
	}
	data, _ := json.Marshal(sev)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	html := strings.ReplaceAll(chartTemplate, "__DATA__", string(data))
	_, _ = w.Write([]byte(html))
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

const chartTemplate = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Gráfico de Severidad</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#fafafa;display:flex;align-items:center;justify-content:center;height:100vh;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif}.chart-wrapper{width:100%;height:280px;position:relative}.no-data{text-align:center;color:#999;font-size:16px;padding:40px}</style>
</head><body><div class="container" style="width:100%;height:100%;padding:20px;display:flex;flex-direction:column;align-items:center;justify-content:center">
<script>
const severidad = __DATA__;
document.addEventListener('DOMContentLoaded', function() {
  const labels = Object.keys(severidad);
  const vals = Object.values(severidad);
  if (labels.length === 1 && labels[0] === 'Sin datos') {
    document.body.innerHTML = '<div class="no-data">📊 No hay vulnerabilidades registradas</div>';
    return;
  }
  const colors = {'Crítica':'#e74c3c','Alta':'#e67e22','Media':'#f1c40f','Baja':'#3498db'};
  const bg = labels.map(l => colors[l] || '#95a5a6');
  const total = vals.reduce((a,b)=>a+b,0);
  const canvas = document.createElement('canvas');
  document.querySelector('.container').appendChild(canvas);
  new Chart(canvas, { type:'doughnut', data:{ labels: labels.map(l=>l+' ('+vals[labels.indexOf(l)]+')'), datasets:[{data:vals,backgroundColor:bg,borderWidth:3,borderColor:'white',hoverOffset:10}]},
    options:{ responsive:true, maintainAspectRatio:true, cutout:'65%', plugins:{ legend:{position:'bottom',labels:{usePointStyle:true,padding:15,font:{size:11}}}, tooltip:{backgroundColor:'rgba(0,0,0,0.8)',padding:10,cornerRadius:8, callbacks:{ label:function(c){let v=c.parsed||0;let p=total>0?((v/total)*100).toFixed(1):0;return c.label+': '+v+' ('+p+'%)';}}}}}});
});
</script></div></body></html>`
