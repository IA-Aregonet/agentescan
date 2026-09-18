package scanner

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"sync"

	"agente-seguridad/internal/models"
)

// ChangeMonitor tracks content hashes per URL across scans.
type ChangeMonitor struct {
	mu     sync.Mutex
	states map[string]string
	dir    string
}

// NewChangeMonitor loads previous hashes from dir/estado_anterior.json.
func NewChangeMonitor(dir string) *ChangeMonitor {
	m := &ChangeMonitor{states: map[string]string{}, dir: dir}
	path := dir + "/estado_anterior.json"
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &m.states)
	}
	return m
}

// Check compares the current content hash of url against the stored one and
// updates the stored state.
func (m *ChangeMonitor) Check(rawURL string) models.Cambio {
	hash := contentHash(rawURL)
	if hash == "" {
		return models.Cambio{Cambio: false, Error: "No se pudo acceder a la URL"}
	}

	m.mu.Lock()
	prev, had := m.states[rawURL]
	m.states[rawURL] = hash
	m.saveLocked()
	m.mu.Unlock()

	if !had {
		return models.Cambio{Cambio: false, Mensaje: "Primera vez que se escanea este sitio"}
	}
	if prev != hash {
		return models.Cambio{Cambio: true, Mensaje: "¡El contenido cambió!", HashAnterior: prev, HashActual: hash}
	}
	return models.Cambio{Cambio: false, Mensaje: "Sin cambios"}
}

func (m *ChangeMonitor) saveLocked() {
	data, _ := json.MarshalIndent(m.states, "", "  ")
	_ = os.MkdirAll(m.dir, 0o755)
	_ = os.WriteFile(m.dir+"/estado_anterior.json", data, 0o644)
}

func contentHash(rawURL string) string {
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
	if resp.StatusCode != 200 {
		return ""
	}
	body := readBody(resp)
	sum := md5.Sum([]byte(body))
	return hex.EncodeToString(sum[:])
}
