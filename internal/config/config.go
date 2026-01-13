package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port             string
	S3Endpoint       string
	S3Bucket         string
	S3AccessKey      string
	S3SecretKey      string
	S3Region         string
	RedisURL         string
	CacheTTL         time.Duration
	MaxCacheSize     int64
	AllowedOrigins   []string
	EnableCompression bool
	EnableRangeRequests bool
}

func Load() *Config {
	cacheTTL, _ := strconv.Atoi(getEnv("CACHE_TTL_HOURS", "24"))
	maxCacheSize, _ := strconv.ParseInt(getEnv("MAX_CACHE_SIZE_MB", "1024"), 10, 64)

	return &Config{
		Port:             getEnv("PORT", "4012"),
		S3Endpoint:       getEnv("S3_ENDPOINT", "http://localhost:9000"),
		S3Bucket:         getEnv("S3_BUCKET", "quickchat-attachments"),
		S3AccessKey:      getEnv("S3_ACCESS_KEY", "minioadmin"),
		S3SecretKey:      getEnv("S3_SECRET_KEY", "minioadmin"),
		S3Region:         getEnv("S3_REGION", "us-east-1"),
		RedisURL:         getEnv("REDIS_URL", "localhost:6379"),
		CacheTTL:         time.Duration(cacheTTL) * time.Hour,
		MaxCacheSize:     maxCacheSize * 1024 * 1024, // Convert MB to bytes
		AllowedOrigins:   []string{"*"},
		EnableCompression: getEnv("ENABLE_COMPRESSION", "true") == "true",
		EnableRangeRequests: getEnv("ENABLE_RANGE_REQUESTS", "true") == "true",
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
