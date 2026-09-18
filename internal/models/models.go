package models

// Vulnerabilidad is a vulnerability finding discovered during a scan.
type Vulnerabilidad struct {
	Tipo      string `json:"tipo"`
	Severidad string `json:"severidad"`
	Parametro string `json:"parametro"`
	Payload   string `json:"payload"`
	Evidencia string `json:"evidencia"`
	URL       string `json:"url"`
}

// PortInfo describes a single open port.
type PortInfo struct {
	Servicio string `json:"servicio"`
	Estado   string `json:"estado"`
	Producto string `json:"producto"`
	Version  string `json:"version"`
}

// Directorio is a discovered directory/route.
type Directorio struct {
	URL        string `json:"url"`
	Method     string `json:"method"`
	Status     int    `json:"status"`
	Tamano     int    `json:"tamano"`
	Encontrado bool   `json:"encontrado"`
}

// Tech is a detected technology with its evidence.
type Tech struct {
	Fuente    string `json:"fuente"`
	Evidencia string `json:"evidencia"`
}

// Subdominio is a DNS/HTTP subdomain check result.
type Subdominio struct {
	Subdominio      string `json:"subdominio"`
	DominioCompleto string `json:"dominio_completo"`
	Existe          bool   `json:"existe"`
	IP              string `json:"ip"`
	CNAME           string `json:"cname"`
	Servicio        string `json:"servicio"`
	TakeoverPosible bool   `json:"takeover_posible"`
	HTTPStatus      int    `json:"http_status"`
}

// Hallazgo is a source-code finding.
type Hallazgo struct {
	Categoria   string `json:"categoria"`
	Descripcion string `json:"descripcion"`
	Valor       string `json:"valor"`
	Fuente      string `json:"fuente"`
	Severidad   string `json:"severidad"`
	Hash        string `json:"hash"`
}

// Cambio is the outcome of change monitoring.
type Cambio struct {
	Cambio       bool   `json:"cambio"`
	Mensaje      string `json:"mensaje"`
	HashAnterior string `json:"hash_anterior"`
	HashActual   string `json:"hash_actual"`
	Error        string `json:"error,omitempty"`
}

// Resultado de una prueba de CORS.
type PruebaCORS struct {
	Tipo        string `json:"tipo"`
	Descripcion string `json:"descripcion"`
	Origin      string `json:"origin"`
	Severidad   string `json:"severidad"`
}

// VulnerabilityMap encapsulates grouped severity counts.
type VulnerabilityMap struct {
	URL              string           `json:"url"`
	Vulnerabilidades []Vulnerabilidad `json:"vulnerabilidades"`
	Total            int              `json:"total"`
	Criticas         int              `json:"criticas"`
	Altas            int              `json:"altas"`
	Medias           int              `json:"medias"`
	Bajas            int              `json:"bajas"`
}

// Resultado de un escaneo completo sobre un sitio.
type Resultado struct {
	URL              string           `json:"url"`
	Timestamp        string           `json:"timestamp"`
	Puertos          PortScanResult   `json:"puertos"`
	Directorios      DirFuzzResult    `json:"directorios"`
	Vulnerabilidades VulnerabilityMap `json:"vulnerabilidades"`
	Cambios          *Cambio          `json:"cambios"`
	Tecnologias      TechResult       `json:"tecnologias"`
	CSRF             CSRFResult       `json:"csrf"`
	GraphQL          GraphQLResult    `json:"graphql"`
	WebSocket        WebSocketResult  `json:"websocket"`
	RaceConditions   RaceResult       `json:"race_conditions"`
	CachePoisoning   CacheResult      `json:"cache_poisoning"`
	Subdomains       SubdomainResult  `json:"subdomain_takeover"`
	CORS             CORSResult       `json:"cors"`
	CodigoFuente     SourceResult     `json:"codigo_fuente"`
}

type PortScanResult struct {
	Host            string           `json:"host"`
	PuertosAbiertos []int            `json:"puertos_abiertos"`
	TotalAbiertos   int              `json:"total_abiertos"`
	Servicios       map[int]PortInfo `json:"servicios"`
	EscaneoExitoso  bool             `json:"escaneo_exitoso"`
	Error           string           `json:"error,omitempty"`
}

type DirFuzzResult struct {
	URLBase                string       `json:"url_base"`
	DirectoriosEncontrados []Directorio `json:"directorios_encontrados"`
	TotalEncontrados       int          `json:"total_encontrados"`
}

type TechResult struct {
	URL         string          `json:"url"`
	Tecnologias map[string]Tech `json:"tecnologias"`
	Total       int             `json:"total"`
}

type CSRFResult struct {
	URL             string   `json:"url"`
	CSRFProtegidos  int      `json:"csrf_protegidos"`
	CSRFVulnerables int      `json:"csrf_vulnerables"`
	Recomendaciones []string `json:"recomendaciones"`
}

type GraphQLResult struct {
	URL              string           `json:"url"`
	EsGraphQL        bool             `json:"es_graphql"`
	Vulnerabilidades []Vulnerabilidad `json:"vulnerabilidades"`
}

type WebSocketResult struct {
	URL              string           `json:"url"`
	WebSockets       []string         `json:"websockets"`
	TotalEncontrados int              `json:"total_encontrados"`
	Vulnerabilidades []Vulnerabilidad `json:"vulnerabilidades"`
}

type RaceResult struct {
	URL                string           `json:"url"`
	EndpointsSensibles []string         `json:"endpoints_sensibles"`
	Vulnerabilidades   []Vulnerabilidad `json:"vulnerabilidades"`
}

type CacheResult struct {
	URL              string           `json:"url"`
	UsaCache         bool             `json:"usa_cache"`
	TipoCache        string           `json:"tipo_cache"`
	Vulnerabilidades []Vulnerabilidad `json:"vulnerabilidades"`
}

type SubdomainResult struct {
	Dominio                     string           `json:"dominio"`
	SubdominiosAnalizados       []Subdominio     `json:"subdominios_analizados"`
	Vulnerabilidades            []Vulnerabilidad `json:"vulnerabilidades"`
	TotalTakeovers              int              `json:"total_takeovers"`
	TotalSubdominiosEncontrados int              `json:"total_subdominios_encontrados"`
}

type CORSResult struct {
	URL              string           `json:"url"`
	Pruebas          []PruebaCORS     `json:"pruebas"`
	Vulnerabilidades []Vulnerabilidad `json:"vulnerabilidades"`
}

type SourceResult struct {
	URL                string                `json:"url"`
	Encontrados        map[string][]Hallazgo `json:"encontrados"`
	Total              int                   `json:"total"`
	ArchivosAnalizados int                   `json:"archivos_analizados"`
	Vulnerabilidades   []Vulnerabilidad      `json:"vulnerabilidades"`
}
