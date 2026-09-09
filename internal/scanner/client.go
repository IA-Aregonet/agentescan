package scanner

import (
	"crypto/tls"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client returns a shared HTTP client that skips TLS verification (matching the
// original Python behavior) and applies the configured timeout.
func Client(timeoutSec int) *http.Client {
	if timeoutSec <= 0 {
		timeoutSec = 10
	}
	return &http.Client{
		Timeout: time.Duration(timeoutSec) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// UA is the browser-like User-Agent used across requests.
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// BaseHeaders returns a set of common request headers.
func BaseHeaders() http.Header {
	h := http.Header{}
	h.Set("User-Agent", UA)
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	h.Set("Accept-Language", "es-ES,es;q=0.9,en;q=0.8")
	h.Set("Accept-Encoding", "gzip, deflate, br")
	h.Set("Connection", "keep-alive")
	return h
}

// HostFromURL extracts the host (without port) from a URL string.
func HostFromURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// DomainFromURL extracts the bare domain (hostname) from a URL.
func DomainFromURL(raw string) string {
	return HostFromURL(raw)
}

// EnsureScheme prefixes https:// when no scheme is present.
func EnsureScheme(raw string) string {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "https://" + raw
	}
	return raw
}

// httpReq builds a GET request with base headers for the given URL.
func httpReq(rawURL string) (*http.Request, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header = BaseHeaders()
	return req, nil
}
