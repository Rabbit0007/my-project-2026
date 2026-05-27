package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"shenji/backend/internal/config"
	"shenji/backend/internal/database"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	cfg := config.Load()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("connect database")
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	log.Info().Msg("agent worker ready; API process currently dispatches first-stage runs asynchronously")
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			log.Info().Msg("worker heartbeat")
		case <-stop:
			log.Info().Msg("worker stopped")
			return
		}
	}
}
