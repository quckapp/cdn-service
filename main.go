package main

import (
	"log"
	"os"

	"cdn-service/internal/api"
	"cdn-service/internal/cache"
	"cdn-service/internal/config"
	"cdn-service/internal/storage"

	"github.com/gin-gonic/gin"
)

func main() {
	cfg := config.Load()

	// Initialize storage backend (S3-compatible)
	storageBackend, err := storage.NewS3Storage(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}

	// Initialize Redis cache
	cacheBackend, err := cache.NewRedisCache(cfg.RedisURL)
	if err != nil {
		log.Printf("Warning: Failed to initialize cache: %v", err)
	}

	// Setup HTTP server
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()
	api.RegisterRoutes(router, storageBackend, cacheBackend, cfg)

	// TODO: promotion-gate requires SQL or MongoDB store
	// Once cdn-service has a suitable database connection, initialize:
	// promoStore := promotiongate.NewSQLStore(db, "")
	// promoStore.Migrate(context.Background())
	// promoHandler := promotiongate.NewHandler(promoStore, "cdn-service", os.Getenv("ENVIRONMENT"))
	// promoHandler.RegisterRoutes(router.Group("/api/v1"))

	port := cfg.Port
	log.Printf("CDN service starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
