# Agente de Seguridad (Go)

Portabilidad a Go del agente de pentesting original (Python + PHP). Aprovecha la
concurrencia de Go (goroutines + worker pools) para ejecutar los escaneos en
paralelo. Incluye un dashboard web servido por el propio binario, persistencia en
MySQL y notificaciones por Telegram.

## Módulos de escaneo

- Puertos (TCP connect, concurrente)
- Fuzzing de directorios (wordlist, concurrente)
- XSS / SQLi / Path Traversal / SSTI / LFI / Comandos / CRLF / Open Redirect / XXE / SSRF
- Headers de seguridad ausentes
- Tecnologías detectadas
- CSRF, GraphQL, WebSockets, Race Conditions, Cache Poisoning, CORS
- Subdomain takeover (DNS + HTTP)
- Análisis de código fuente (API keys, tokens, credenciales, IPs, `eval/exec`, etc.)

## Despliegue en Coolify

Opción recomendada: **Docker Compose** (MySQL + app) o **Dockerfile** directo.
En Coolify crea un recurso y apunta al repositorio; define las variables de
`docker-compose.yml` desde el `.env.example` (sobre todo `TELEGRAM_BOT_TOKEN`,
`TELEGRAM_CHAT_ID` y las contraseñas de MySQL).

```bash
# Local (requiere Docker)
docker compose up --build

# Especificar secreto de Telegram
TELEGRAM_BOT_TOKEN=xxx TELEGRAM_CHAT_ID=yyy docker compose up --build
```

El dashboard queda en `http://<host>:8080/`. Desde ahí puedes agregar un sitio y
disparar un escaneo; el agente también escanea todos los sitios activos cada
`SCAN_INTERVAL_SECONDS` (por defecto 5 horas).

## Variables de entorno

| Variable | Descripción | Default |
|----------|-------------|---------|
| `PORT` | Puerto HTTP del dashboard | `8080` |
| `DB_HOST` / `DB_PORT` | Host/port de MySQL | `mysql` / `3306` |
| `DB_USER` / `DB_PASSWORD` / `DB_NAME` | Credenciales MySQL | `agente_user` / `agente_seguridad` / `agente_seguridad` |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Notificaciones Telegram | vacío (desactivado) |
| `SCAN_INTERVAL_SECONDS` | Intervalo de escaneo automático | `18000` |
| `MAX_WORKERS` | Concurrencia (goroutines) | `50` |
| `REQUEST_TIMEOUT` | Timeout HTTP por petición | `10` |
| `REPORTS_DIR` | Directorio de reportes CSV | `reportes` |
| `WORDLIST_PATH` | Wordlist de directorios | `wordlists/directorios_comunes.txt` |

## Desarrollo

```bash
go mod tidy
go build -o agente-seguridad.exe ./cmd/agent
go vet ./...
```
