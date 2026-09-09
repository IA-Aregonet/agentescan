package config

import (
	"os"
	"strconv"
)

// Config holds all runtime configuration, loaded from environment variables.
type Config struct {
	// HTTP
	Port string

	// MySQL
	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string

	// Telegram (optional)
	TelegramEnabled bool
	TelegramToken   string
	TelegramChatID  string

	// Agent behavior
	ScanIntervalSeconds int
	MaxWorkers          int
	RequestTimeout      int
	ReportsDir          string
	WordlistPath        string
}

// DefaultConfig returns configuration populated from environment variables,
// falling back to sane defaults suited for local/Docker development.
func DefaultConfig() Config {
	return Config{
		Port:                getEnv("PORT", "8080"),
		DBHost:              getEnv("DB_HOST", "mysql"),
		DBPort:              getEnv("DB_PORT", "3306"),
		DBUser:              getEnv("DB_USER", "agente_user"),
		DBPassword:          getEnv("DB_PASSWORD", "agente_seguridad"),
		DBName:              getEnv("DB_NAME", "agente_seguridad"),
		TelegramToken:       getEnv("TELEGRAM_BOT_TOKEN", ""),
		TelegramChatID:      getEnv("TELEGRAM_CHAT_ID", ""),
		ScanIntervalSeconds: getEnvInt("SCAN_INTERVAL_SECONDS", 18000),
		MaxWorkers:          getEnvInt("MAX_WORKERS", 50),
		RequestTimeout:      getEnvInt("REQUEST_TIMEOUT", 10),
		ReportsDir:          getEnv("REPORTS_DIR", "reportes"),
		WordlistPath:        getEnv("WORDLIST_PATH", "wordlists/directorios_comunes.txt"),
	}
}

// TelegramEnabled resolves the effective flag: enabled when a token is set.
func (c Config) TelegramConfigured() bool {
	return c.TelegramToken != "" && c.TelegramChatID != ""
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}
