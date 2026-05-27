package main

import (
	"context"
	"os"

	"shenji/backend/internal/api"
	"shenji/backend/internal/config"
	"shenji/backend/internal/database"
	"shenji/backend/internal/runner"
	"shenji/backend/internal/service"
	"shenji/backend/internal/storage"
	"shenji/backend/internal/tools"

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
	if err := database.AutoMigrate(db); err != nil {
		log.Fatal().Err(err).Msg("migrate database")
	}
	var store storage.ArtifactStore
	switch cfg.ArtifactStoreType {
	case "local":
		store, err = storage.NewLocalStore(cfg.ArtifactRoot, cfg.PublicBaseURL)
	default:
		store, err = storage.NewMinIOStore(context.Background(), cfg)
	}
	if err != nil {
		log.Fatal().Err(err).Msg("init artifact store")
	}
	workspace := runner.NewWorkspaceManager(cfg.WorkspaceRoot)
	manager := runner.NewRunnerManager(cfg)
	registry := tools.DefaultRegistry(cfg, manager)
	services := service.NewServices(cfg, db, store, workspace, registry)
	if err := services.Auth.EnsureDefaultUser(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("ensure default user")
	}
	if err := services.Task.RecoverInterrupted(context.Background()); err != nil {
		log.Fatal().Err(err).Msg("recover interrupted tasks")
	}
	router := api.NewRouter(cfg, services)
	log.Info().Str("addr", cfg.ServerAddr).Msg("starting backend")
	if err := router.Run(cfg.ServerAddr); err != nil {
		log.Fatal().Err(err).Msg("backend stopped")
	}
}
