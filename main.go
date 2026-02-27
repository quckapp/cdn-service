package main

import (
	"context"
	"database/sql"
	"log"
	"os"

	"cdn-service/internal/api"
	"cdn-service/internal/cache"
	"cdn-service/internal/config"
	"cdn-service/internal/storage"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	promotiongate "github.com/quckapp/promotion-gate-go"
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

	// Promotion gate (uses dedicated MySQL connection)
	if promoDSN := os.Getenv("PROMOTION_DB_URL"); promoDSN != "" {
		promoDB, err := sql.Open("mysql", promoDSN)
		if err != nil {
			log.Printf("Warning: Failed to connect promotion DB: %v", err)
		} else {
			promoStore := promotiongate.NewSQLStore(promoDB, "")
			if err := promoStore.Migrate(context.Background()); err != nil {
				log.Printf("Warning: Failed to migrate promotion tables: %v", err)
			}
			promoHandler := promotiongate.NewHandler(promoStore, "cdn-service", os.Getenv("ENVIRONMENT"))
			promoHandler.RegisterRoutes(router.Group("/api/v1"))
			log.Println("Promotion gate enabled")
		}
	}

	port := cfg.Port
	log.Printf("CDN service starting on port %s", port)
	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
