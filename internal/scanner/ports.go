package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"agente-seguridad/internal/models"
)

// commonPorts is the port set checked when no explicit list is provided.
var commonPorts = []int{
	20, 21, 22, 23, 25, 53, 67, 68, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
	110, 135, 137, 138, 139, 143, 389, 443, 445, 465, 500, 587, 636, 993, 995,
	1194, 1433, 1434, 1521, 1701, 1723, 2003, 2004, 2181, 2222, 2375, 2376,
	26379, 3000, 3306, 3307, 3308, 3389, 4500, 4848, 5000, 5044, 51820,
	5432, 5433, 5434, 5601, 5672, 5900, 5901, 5902, 5984, 6379, 6380, 6381,
	6443, 6984, 7000, 7474, 7687, 8000, 8005, 8009, 8080, 8081, 8082, 8086,
	8089, 8443, 8787, 8888, 9000, 9001, 9042, 9090, 9092, 9200, 9300, 9418,
	9990, 10250, 10255, 11211, 15672, 27017, 27018, 27019, 27020,
}

// ScanPorts performs a concurrent TCP-connect scan of the common ports for the
// given URL host, returning the open ports and their guessed services.
func ScanPorts(rawURL string, workers int) models.PortScanResult {
	host := HostFromURL(rawURL)
	res := models.PortScanResult{
		Host:           host,
		Servicios:      map[int]models.PortInfo{},
		EscaneoExitoso: true,
	}
	if host == "" {
		res.Error = "no host"
		return res
	}

	if workers <= 0 {
		workers = 80
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for _, p := range commonPorts {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
			conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			res.PuertosAbiertos = append(res.PuertosAbiertos, port)
			res.Servicios[port] = models.PortInfo{
				Servicio: serviceName(port),
				Estado:   "open",
			}
			mu.Unlock()
		}(p)
	}
	wg.Wait()

	res.TotalAbiertos = len(res.PuertosAbiertos)
	return res
}

// serviceName maps a port to a best-effort service name (identical mapping to
// the original Python implementation).
func serviceName(port int) string {
	m := map[int]string{
		20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
		53: "dns", 80: "http", 110: "pop3", 135: "msrpc", 137: "netbios-ns",
		138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 389: "ldap",
		443: "https", 445: "microsoft-ds", 465: "smtps", 587: "smtp",
		636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s",
		1434: "ms-sql-m", 1521: "oracle", 1723: "pptp", 3306: "mysql",
		3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc",
		6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
	}
	if s, ok := m[port]; ok {
		return s
	}
	return "desconocido"
}
