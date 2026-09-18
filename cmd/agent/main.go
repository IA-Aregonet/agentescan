package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agente-seguridad/internal/agent"
	"agente-seguridad/internal/config"
	"agente-seguridad/internal/db"
	"agente-seguridad/internal/httpapi"
	"agente-seguridad/internal/notifier"
	"agente-seguridad/internal/reports"
	"agente-seguridad/web"
)

func main() {
	cfg := config.DefaultConfig()

	store, err := db.Connect(cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName)
	if err != nil {
		log.Fatalf("❌ MySQL no disponible: %v", err)
	}
	defer store.DB.Close()

	if err := store.EnsureSchema(); err != nil {
		log.Fatalf("❌ Error inicializando esquema: %v", err)
	}
	log.Println("✅ Conexión a MySQL establecida")

	notes := notifier.New(cfg.TelegramToken, cfg.TelegramChatID)
	rep := reports.New(store, cfg.ReportsDir)
	ag := agent.New(cfg, store, notes, rep)

	// HTTP server (dashboard + API).
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      httpapi.New(store, ag, web.FS),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 90 * time.Second,
	}

	// Background scheduler scans all active sites on an interval.
	ctx, cancel := context.WithCancel(context.Background())
	go scheduler(ctx, cfg, store, ag)

	go func() {
		log.Printf("🌐 Dashboard en http://localhost:%s/", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("❌ Servidor HTTP: %v", err)
		}
	}()

	// Graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("⏹️ Deteniendo...")
	cancel()

	shutCtx, shutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdown()
	_ = srv.Shutdown(shutCtx)
}

// scheduler periodically scans all active sites, sending telemetry on each cycle.
func scheduler(ctx context.Context, cfg config.Config, store *db.Store, ag *agent.Agent) {
	interval := time.Duration(cfg.ScanIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run an initial pass shortly after startup.
	time.Sleep(3 * time.Second)
	runCycle(store, ag)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCycle(store, ag)
		}
	}
}

func runCycle(store *db.Store, ag *agent.Agent) {
	sitios, err := store.SitiosActivos()
	if err != nil {
		log.Printf("scheduler error listando sitios: %v", err)
		return
	}
	if len(sitios) == 0 {
		log.Println("⚠️ No hay sitios activos. Esperando...")
		return
	}
	log.Printf("🔄 Ciclo - escaneando %d sitios", len(sitios))
	for _, s := range sitios {
		log.Printf("🔍 Escaneando: %s", s.URL)
		if err := ag.RunScan(s.ID); err != nil {
			log.Printf("sitio %d error: %v", s.ID, err)
		}
	}
}
