package scanner

import (
	"bufio"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"

	"agente-seguridad/internal/models"
)

// LoadWordlist reads a newline-separated wordlist, skipping comments and blanks.
// It falls back to a small builtin list if the file is missing or empty.
func LoadWordlist(path string) []string {
	var words []string
	f, err := os.Open(path)
	if err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			words = append(words, line)
		}
	}
	if len(words) == 0 {
		words = []string{"admin", "login", "wp-admin", "backup", "config", "sql", "test", "dev", "api"}
	}
	return dedup(words)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, w := range in {
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out
}

// FuzzDirectorios concurrently probes each wordlist entry against baseURL.
func FuzzDirectorios(baseURL string, wordlist []string, workers int) models.DirFuzzResult {
	res := models.DirFuzzResult{URLBase: baseURL}

	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}

	if workers <= 0 {
		workers = 50
	}

	client := Client(5)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)

	for _, w := range wordlist {
		wg.Add(1)
		go func(word string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			d := probeDir(baseURL, word, client)
			if d == nil {
				return
			}
			mu.Lock()
			res.DirectoriosEncontrados = append(res.DirectoriosEncontrados, *d)
			res.TotalEncontrados++
			mu.Unlock()
		}(w)
	}
	wg.Wait()

	// Sort: 200 first, then 3xx redirects, then 4xx.
	sort.SliceStable(res.DirectoriosEncontrados, func(i, j int) bool {
		return rankStatus(res.DirectoriosEncontrados[i].Status) < rankStatus(res.DirectoriosEncontrados[j].Status)
	})
	return res
}

func rankStatus(s int) int {
	switch s {
	case 200:
		return 0
	case 301, 302, 307, 308:
		return 1
	case 401, 403:
		return 2
	default:
		return 3
	}
}

// probeDir tests a single word with several URL variations, returning the first hit.
func probeDir(baseURL, word string, client *http.Client) *models.Directorio {
	variations := []string{
		word,
		word + "/",
		word + "?",
		word + "?test=1",
		word + "/?test=1",
	}
	for _, v := range variations {
		u, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		// url.JoinPath encodes correctly; combine base path + variation.
		joined := strings.TrimSuffix(baseURL, "/") + "/" + strings.TrimPrefix(v, "/")
		_ = u
		req, err := http.NewRequest(http.MethodGet, joined, nil)
		if err != nil {
			continue
		}
		req.Header = BaseHeaders()
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if isInterestingStatus(resp.StatusCode) {
			return &models.Directorio{
				URL:        joined,
				Method:     http.MethodGet,
				Status:     resp.StatusCode,
				Tamano:     len(body),
				Encontrado: true,
			}
		}
	}
	return nil
}

func isInterestingStatus(code int) bool {
	switch code {
	case 200, 201, 202, 203, 204, 205, 206,
		301, 302, 303, 307, 308,
		401, 402, 403, 405, 406, 407, 408:
		return true
	}
	return false
}
