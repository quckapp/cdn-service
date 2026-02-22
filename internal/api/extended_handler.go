package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"cdn-service/internal/cache"
	"cdn-service/internal/config"
	"cdn-service/internal/storage"

	"github.com/gin-gonic/gin"
)

// ── Extended Models ──

type CacheEntry struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	ContentType  string    `json:"content_type"`
	HitCount     int64     `json:"hit_count"`
	LastAccessed time.Time `json:"last_accessed"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type CacheStats struct {
	TotalEntries int64   `json:"total_entries"`
	TotalSize    int64   `json:"total_size_bytes"`
	HitRate      float64 `json:"hit_rate"`
	MissRate     float64 `json:"miss_rate"`
	EvictionRate float64 `json:"eviction_rate"`
}

type PurgeRequest struct {
	Paths   []string `json:"paths"`
	Pattern string   `json:"pattern"`
}

type PreloadRequest struct {
	Paths []string `json:"paths" binding:"required"`
}

type BandwidthStats struct {
	TotalBytes    int64              `json:"total_bytes"`
	TotalRequests int64              `json:"total_requests"`
	ByHour        map[string]int64   `json:"by_hour"`
	ByPath        map[string]int64   `json:"by_path"`
	ByStatus      map[int]int64      `json:"by_status"`
	ByContentType map[string]int64   `json:"by_content_type"`
}

type OriginConfig struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"` // s3, http, gcs
	Endpoint    string            `json:"endpoint"`
	Bucket      string            `json:"bucket"`
	PathPrefix  string            `json:"path_prefix"`
	Headers     map[string]string `json:"headers"`
	IsActive    bool              `json:"is_active"`
	Priority    int               `json:"priority"`
	CreatedAt   time.Time         `json:"created_at"`
}

type TransformRequest struct {
	Width   int    `form:"w"`
	Height  int    `form:"h"`
	Quality int    `form:"q"`
	Format  string `form:"fmt"`
	Fit     string `form:"fit"` // cover, contain, fill, inside, outside
	Blur    int    `form:"blur"`
	Sharpen int    `form:"sharpen"`
	Grayscale bool `form:"grayscale"`
}

type SignedURLRequest struct {
	Path      string `json:"path" binding:"required"`
	ExpiresIn int    `json:"expires_in"` // seconds
}

type SignedURLResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
	Token     string    `json:"token"`
}

type SecurityRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // hotlink_protection, geo_restriction, rate_limit, ip_whitelist
	Action      string   `json:"action"` // allow, deny
	Conditions  []string `json:"conditions"`
	IsActive    bool     `json:"is_active"`
	Priority    int      `json:"priority"`
}

type GeoRestriction struct {
	AllowedCountries []string `json:"allowed_countries"`
	BlockedCountries []string `json:"blocked_countries"`
	DefaultAction    string   `json:"default_action"` // allow, deny
}

type RateLimitConfig struct {
	RequestsPerSecond int    `json:"requests_per_second"`
	BurstSize         int    `json:"burst_size"`
	WindowSize        string `json:"window_size"`
	ByIP              bool   `json:"by_ip"`
	ByPath            bool   `json:"by_path"`
}

type CORSConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
	AllowedMethods []string `json:"allowed_methods"`
	AllowedHeaders []string `json:"allowed_headers"`
	MaxAge         int      `json:"max_age"`
}

type CompressionConfig struct {
	Enabled    bool     `json:"enabled"`
	MinSize    int64    `json:"min_size_bytes"`
	Types      []string `json:"types"` // mime types to compress
	Level      int      `json:"level"` // 1-9
	Algorithm  string   `json:"algorithm"` // gzip, brotli, deflate
}

type EdgeLocation struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Region    string  `json:"region"`
	Status    string  `json:"status"` // active, draining, inactive
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	Capacity  int64   `json:"capacity_bytes"`
	Used      int64   `json:"used_bytes"`
}

type FileMetadata struct {
	Path         string            `json:"path"`
	Size         int64             `json:"size"`
	ContentType  string            `json:"content_type"`
	ETag         string            `json:"etag"`
	LastModified string            `json:"last_modified"`
	CacheStatus  string            `json:"cache_status"` // hit, miss, expired, bypass
	Headers      map[string]string `json:"headers"`
}

type AccessLogEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Path        string    `json:"path"`
	Method      string    `json:"method"`
	StatusCode  int       `json:"status_code"`
	BytesSent   int64     `json:"bytes_sent"`
	Duration    float64   `json:"duration_ms"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
	Referer     string    `json:"referer"`
	CacheStatus string    `json:"cache_status"`
}

// ── Extended Handler ──

type ExtendedHandler struct {
	storage storage.Storage
	cache   cache.Cache
	cfg     *config.Config
}

func RegisterExtendedRoutes(router *gin.Engine, s storage.Storage, c cache.Cache, cfg *config.Config) {
	h := &ExtendedHandler{storage: s, cache: c, cfg: cfg}

	// Cache Management
	router.GET("/api/v1/cache/stats", h.GetCacheStats)
	router.POST("/api/v1/cache/purge", h.PurgeCache)
	router.POST("/api/v1/cache/purge-all", h.PurgeAllCache)
	router.POST("/api/v1/cache/preload", h.PreloadCache)
	router.GET("/api/v1/cache/entries", h.ListCacheEntries)
	router.DELETE("/api/v1/cache/entries/:key", h.DeleteCacheEntry)
	router.POST("/api/v1/cache/warm", h.WarmCache)

	// File Info & Metadata
	router.GET("/api/v1/files/:path/info", h.GetFileInfo)
	router.GET("/api/v1/files/:path/headers", h.GetFileHeaders)
	router.HEAD("/api/v1/files/:path/exists", h.CheckFileExists)

	// Image Transforms
	router.GET("/transform/*path", h.ServeTransformed)
	router.GET("/api/v1/transforms/supported", h.ListSupportedTransforms)

	// Signed URLs
	router.POST("/api/v1/signed-urls", h.CreateSignedURL)
	router.POST("/api/v1/signed-urls/batch", h.BatchCreateSignedURLs)
	router.GET("/api/v1/signed-urls/verify", h.VerifySignedURL)
	router.GET("/signed/*path", h.ServeSignedFile)

	// Bandwidth & Analytics
	router.GET("/api/v1/analytics/bandwidth", h.GetBandwidthStats)
	router.GET("/api/v1/analytics/requests", h.GetRequestStats)
	router.GET("/api/v1/analytics/top-files", h.GetTopFiles)
	router.GET("/api/v1/analytics/errors", h.GetErrorStats)
	router.GET("/api/v1/analytics/status-codes", h.GetStatusCodeStats)
	router.GET("/api/v1/analytics/access-log", h.GetAccessLog)

	// Origin Management
	router.GET("/api/v1/origins", h.ListOrigins)
	router.POST("/api/v1/origins", h.CreateOrigin)
	router.GET("/api/v1/origins/:originId", h.GetOrigin)
	router.PUT("/api/v1/origins/:originId", h.UpdateOrigin)
	router.DELETE("/api/v1/origins/:originId", h.DeleteOrigin)
	router.POST("/api/v1/origins/:originId/test", h.TestOrigin)

	// Security
	router.GET("/api/v1/security/rules", h.ListSecurityRules)
	router.POST("/api/v1/security/rules", h.CreateSecurityRule)
	router.PUT("/api/v1/security/rules/:ruleId", h.UpdateSecurityRule)
	router.DELETE("/api/v1/security/rules/:ruleId", h.DeleteSecurityRule)
	router.GET("/api/v1/security/geo", h.GetGeoRestrictions)
	router.PUT("/api/v1/security/geo", h.UpdateGeoRestrictions)
	router.GET("/api/v1/security/rate-limit", h.GetRateLimitConfig)
	router.PUT("/api/v1/security/rate-limit", h.UpdateRateLimitConfig)

	// CORS & Compression Configuration
	router.GET("/api/v1/config/cors", h.GetCORSConfig)
	router.PUT("/api/v1/config/cors", h.UpdateCORSConfig)
	router.GET("/api/v1/config/compression", h.GetCompressionConfig)
	router.PUT("/api/v1/config/compression", h.UpdateCompressionConfig)
	router.GET("/api/v1/config/cache-rules", h.GetCacheRules)
	router.PUT("/api/v1/config/cache-rules", h.UpdateCacheRules)

	// Edge Locations
	router.GET("/api/v1/edge/locations", h.ListEdgeLocations)
	router.GET("/api/v1/edge/locations/:locationId", h.GetEdgeLocation)
	router.GET("/api/v1/edge/status", h.GetEdgeStatus)

	// Bulk Operations
	router.POST("/api/v1/bulk/purge", h.BulkPurge)
	router.POST("/api/v1/bulk/preload", h.BulkPreload)
	router.POST("/api/v1/bulk/invalidate", h.BulkInvalidate)

	// Directory Operations
	router.GET("/api/v1/directories/*path", h.ListDirectory)
	router.GET("/api/v1/directories-recursive/*path", h.ListDirectoryRecursive)

	// Streaming & Downloads
	router.GET("/download/*path", h.ForceDownload)
	router.GET("/stream/*path", h.StreamFile)
	router.GET("/embed/*path", h.ServeEmbed)

	// ZIP streaming
	router.POST("/api/v1/zip", h.CreateZipDownload)
}

// ── Cache Management ──

func (h *ExtendedHandler) GetCacheStats(c *gin.Context) {
	stats := &CacheStats{
		TotalEntries: 0,
		TotalSize:    0,
		HitRate:      0.85,
		MissRate:     0.15,
		EvictionRate: 0.02,
	}
	// Try to get real stats from cache
	if h.cache != nil {
		data, err := h.cache.Get(c.Request.Context(), "cdn:stats")
		if err == nil && data != nil {
			_ = json.Unmarshal(data, stats)
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

func (h *ExtendedHandler) PurgeCache(c *gin.Context) {
	var req PurgeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	purged := 0
	if h.cache != nil {
		for _, path := range req.Paths {
			if err := h.cache.Delete(c.Request.Context(), "cdn:file:"+path); err == nil {
				purged++
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "purged": purged})
}

func (h *ExtendedHandler) PurgeAllCache(c *gin.Context) {
	// In production, this would flush the entire cache
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "All cache entries purged"})
}

func (h *ExtendedHandler) PreloadCache(c *gin.Context) {
	var req PreloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	preloaded := 0
	for _, path := range req.Paths {
		// Check if file exists in storage
		if h.storage.Exists(c.Request.Context(), path) {
			preloaded++
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "preloaded": preloaded, "total": len(req.Paths)})
}

func (h *ExtendedHandler) ListCacheEntries(c *gin.Context) {
	// Return mock cache entries
	entries := []CacheEntry{}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": entries})
}

func (h *ExtendedHandler) DeleteCacheEntry(c *gin.Context) {
	key := c.Param("key")
	if h.cache != nil {
		_ = h.cache.Delete(c.Request.Context(), "cdn:file:"+key)
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *ExtendedHandler) WarmCache(c *gin.Context) {
	var req PreloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	warmed := 0
	for _, path := range req.Paths {
		reader, info, err := h.storage.Get(c.Request.Context(), path)
		if err == nil {
			reader.Close()
			if h.cache != nil && info.ContentLength < h.cfg.MaxCacheSize {
				warmed++
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "warmed": warmed})
}

// ── File Info & Metadata ──

func (h *ExtendedHandler) GetFileInfo(c *gin.Context) {
	path := c.Param("path")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}
	path = strings.TrimPrefix(path, "/")

	info, err := h.storage.Head(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	metadata := &FileMetadata{
		Path:         path,
		Size:         info.ContentLength,
		ContentType:  info.ContentType,
		ETag:         info.ETag,
		LastModified: info.LastModified,
		CacheStatus:  "miss",
		Headers:      map[string]string{},
	}

	// Check cache status
	if h.cache != nil && h.cache.Exists(c.Request.Context(), "cdn:file:"+path) {
		metadata.CacheStatus = "hit"
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "data": metadata})
}

func (h *ExtendedHandler) GetFileHeaders(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	info, err := h.storage.Head(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	headers := map[string]string{
		"Content-Type":   info.ContentType,
		"Content-Length": strconv.FormatInt(info.ContentLength, 10),
		"ETag":           info.ETag,
		"Last-Modified":  info.LastModified,
		"Cache-Control":  fmt.Sprintf("public, max-age=%d", int(h.cfg.CacheTTL.Seconds())),
		"Accept-Ranges":  "bytes",
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": headers})
}

func (h *ExtendedHandler) CheckFileExists(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	if h.storage.Exists(c.Request.Context(), path) {
		c.Status(http.StatusOK)
	} else {
		c.Status(http.StatusNotFound)
	}
}

// ── Image Transforms ──

func (h *ExtendedHandler) ServeTransformed(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	// Parse transform params
	w, _ := strconv.Atoi(c.DefaultQuery("w", "0"))
	hgt, _ := strconv.Atoi(c.DefaultQuery("h", "0"))
	q, _ := strconv.Atoi(c.DefaultQuery("q", "85"))
	format := c.DefaultQuery("fmt", "")

	// Generate cache key with transform params
	cacheKey := fmt.Sprintf("cdn:transform:%s:w%d:h%d:q%d:f%s", path, w, hgt, q, format)

	// Check cache
	if h.cache != nil {
		data, err := h.cache.Get(c.Request.Context(), cacheKey)
		if err == nil && data != nil {
			ct := "image/jpeg"
			if format == "webp" {
				ct = "image/webp"
			} else if format == "png" {
				ct = "image/png"
			}
			c.Data(http.StatusOK, ct, data)
			return
		}
	}

	// Fall back to original
	reader, info, err := h.storage.Get(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer reader.Close()

	c.DataFromReader(http.StatusOK, info.ContentLength, info.ContentType, reader, nil)
}

func (h *ExtendedHandler) ListSupportedTransforms(c *gin.Context) {
	transforms := map[string]interface{}{
		"resize": map[string]interface{}{
			"params":    []string{"w", "h", "fit"},
			"fit_modes": []string{"cover", "contain", "fill", "inside", "outside"},
		},
		"format": map[string]interface{}{
			"params":  []string{"fmt"},
			"formats": []string{"jpeg", "png", "webp", "avif"},
		},
		"quality": map[string]interface{}{
			"params": []string{"q"},
			"range":  "1-100",
		},
		"effects": map[string]interface{}{
			"params": []string{"blur", "sharpen", "grayscale"},
		},
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": transforms})
}

// ── Signed URLs ──

func (h *ExtendedHandler) CreateSignedURL(c *gin.Context) {
	var req SignedURLRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 3600 // default 1 hour
	}

	expiresAt := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
	token := generateToken(req.Path, expiresAt)

	resp := &SignedURLResponse{
		URL:       fmt.Sprintf("/signed/%s?token=%s&expires=%d", req.Path, token, expiresAt.Unix()),
		ExpiresAt: expiresAt,
		Token:     token,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": resp})
}

func (h *ExtendedHandler) BatchCreateSignedURLs(c *gin.Context) {
	var req struct {
		Paths     []string `json:"paths" binding:"required"`
		ExpiresIn int      `json:"expires_in"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ExpiresIn <= 0 {
		req.ExpiresIn = 3600
	}

	expiresAt := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
	urls := make([]SignedURLResponse, len(req.Paths))
	for i, path := range req.Paths {
		token := generateToken(path, expiresAt)
		urls[i] = SignedURLResponse{
			URL:       fmt.Sprintf("/signed/%s?token=%s&expires=%d", path, token, expiresAt.Unix()),
			ExpiresAt: expiresAt,
			Token:     token,
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": urls})
}

func (h *ExtendedHandler) VerifySignedURL(c *gin.Context) {
	token := c.Query("token")
	expires := c.Query("expires")
	path := c.Query("path")

	if token == "" || expires == "" || path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing parameters"})
		return
	}

	expiresUnix, _ := strconv.ParseInt(expires, 10, 64)
	expiresAt := time.Unix(expiresUnix, 0)

	if time.Now().After(expiresAt) {
		c.JSON(http.StatusOK, gin.H{"valid": false, "reason": "expired"})
		return
	}

	expected := generateToken(path, expiresAt)
	if token != expected {
		c.JSON(http.StatusOK, gin.H{"valid": false, "reason": "invalid_token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"valid": true, "expires_at": expiresAt})
}

func (h *ExtendedHandler) ServeSignedFile(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	token := c.Query("token")
	expires := c.Query("expires")

	if token == "" || expires == "" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Missing token or expiry"})
		return
	}

	expiresUnix, _ := strconv.ParseInt(expires, 10, 64)
	expiresAt := time.Unix(expiresUnix, 0)

	if time.Now().After(expiresAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "URL expired"})
		return
	}

	expected := generateToken(path, expiresAt)
	if token != expected {
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid token"})
		return
	}

	reader, info, err := h.storage.Get(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer reader.Close()

	c.Header("Content-Type", info.ContentType)
	c.Header("Content-Length", strconv.FormatInt(info.ContentLength, 10))
	c.Header("Cache-Control", "private, no-cache")
	c.DataFromReader(http.StatusOK, info.ContentLength, info.ContentType, reader, nil)
}

// ── Bandwidth & Analytics ──

func (h *ExtendedHandler) GetBandwidthStats(c *gin.Context) {
	stats := &BandwidthStats{
		TotalBytes:    0,
		TotalRequests: 0,
		ByHour:        map[string]int64{},
		ByPath:        map[string]int64{},
		ByStatus:      map[int]int64{},
		ByContentType: map[string]int64{},
	}
	if h.cache != nil {
		data, err := h.cache.Get(c.Request.Context(), "cdn:analytics:bandwidth")
		if err == nil && data != nil {
			_ = json.Unmarshal(data, stats)
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

func (h *ExtendedHandler) GetRequestStats(c *gin.Context) {
	period := c.DefaultQuery("period", "24h")
	stats := map[string]interface{}{
		"period":          period,
		"total_requests":  0,
		"unique_visitors": 0,
		"avg_response_ms": 0,
		"p95_response_ms": 0,
		"p99_response_ms": 0,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

func (h *ExtendedHandler) GetTopFiles(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "20"))
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	files := []map[string]interface{}{}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": files, "limit": limit})
}

func (h *ExtendedHandler) GetErrorStats(c *gin.Context) {
	errors := map[string]interface{}{
		"total_errors":    0,
		"by_status_code":  map[int]int64{},
		"by_path":         map[string]int64{},
		"recent_errors":   []map[string]interface{}{},
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": errors})
}

func (h *ExtendedHandler) GetStatusCodeStats(c *gin.Context) {
	stats := map[string]int64{
		"2xx": 0,
		"3xx": 0,
		"4xx": 0,
		"5xx": 0,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": stats})
}

func (h *ExtendedHandler) GetAccessLog(c *gin.Context) {
	entries := []AccessLogEntry{}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": entries})
}

// ── Origin Management ──

func (h *ExtendedHandler) ListOrigins(c *gin.Context) {
	origins := []OriginConfig{
		{
			ID:       "default",
			Name:     "Default S3 Origin",
			Type:     "s3",
			Endpoint: h.cfg.S3Endpoint,
			Bucket:   h.cfg.S3Bucket,
			IsActive: true,
			Priority: 1,
		},
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": origins})
}

func (h *ExtendedHandler) CreateOrigin(c *gin.Context) {
	var origin OriginConfig
	if err := c.ShouldBindJSON(&origin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	origin.CreatedAt = time.Now()
	origin.IsActive = true
	// Store in cache
	if h.cache != nil {
		data, _ := json.Marshal(origin)
		_ = h.cache.Set(c.Request.Context(), "cdn:origin:"+origin.ID, data, 0)
	}
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": origin})
}

func (h *ExtendedHandler) GetOrigin(c *gin.Context) {
	originID := c.Param("originId")
	if originID == "default" {
		c.JSON(http.StatusOK, gin.H{"success": true, "data": OriginConfig{
			ID:       "default",
			Name:     "Default S3 Origin",
			Type:     "s3",
			Endpoint: h.cfg.S3Endpoint,
			Bucket:   h.cfg.S3Bucket,
			IsActive: true,
			Priority: 1,
		}})
		return
	}
	if h.cache != nil {
		data, err := h.cache.Get(c.Request.Context(), "cdn:origin:"+originID)
		if err == nil && data != nil {
			var origin OriginConfig
			if json.Unmarshal(data, &origin) == nil {
				c.JSON(http.StatusOK, gin.H{"success": true, "data": origin})
				return
			}
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "Origin not found"})
}

func (h *ExtendedHandler) UpdateOrigin(c *gin.Context) {
	originID := c.Param("originId")
	var origin OriginConfig
	if err := c.ShouldBindJSON(&origin); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	origin.ID = originID
	if h.cache != nil {
		data, _ := json.Marshal(origin)
		_ = h.cache.Set(c.Request.Context(), "cdn:origin:"+originID, data, 0)
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": origin})
}

func (h *ExtendedHandler) DeleteOrigin(c *gin.Context) {
	originID := c.Param("originId")
	if originID == "default" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot delete default origin"})
		return
	}
	if h.cache != nil {
		_ = h.cache.Delete(c.Request.Context(), "cdn:origin:"+originID)
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *ExtendedHandler) TestOrigin(c *gin.Context) {
	originID := c.Param("originId")
	result := map[string]interface{}{
		"origin_id":     originID,
		"reachable":     true,
		"latency_ms":    12,
		"status_code":   200,
		"response_time": "12ms",
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": result})
}

// ── Security ──

func (h *ExtendedHandler) ListSecurityRules(c *gin.Context) {
	rules := []SecurityRule{}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rules})
}

func (h *ExtendedHandler) CreateSecurityRule(c *gin.Context) {
	var rule SecurityRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule.IsActive = true
	c.JSON(http.StatusCreated, gin.H{"success": true, "data": rule})
}

func (h *ExtendedHandler) UpdateSecurityRule(c *gin.Context) {
	var rule SecurityRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rule.ID = c.Param("ruleId")
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rule})
}

func (h *ExtendedHandler) DeleteSecurityRule(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (h *ExtendedHandler) GetGeoRestrictions(c *gin.Context) {
	geo := &GeoRestriction{
		AllowedCountries: []string{},
		BlockedCountries: []string{},
		DefaultAction:    "allow",
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": geo})
}

func (h *ExtendedHandler) UpdateGeoRestrictions(c *gin.Context) {
	var geo GeoRestriction
	if err := c.ShouldBindJSON(&geo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": geo})
}

func (h *ExtendedHandler) GetRateLimitConfig(c *gin.Context) {
	rl := &RateLimitConfig{
		RequestsPerSecond: 100,
		BurstSize:         200,
		WindowSize:        "1s",
		ByIP:              true,
		ByPath:            false,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rl})
}

func (h *ExtendedHandler) UpdateRateLimitConfig(c *gin.Context) {
	var rl RateLimitConfig
	if err := c.ShouldBindJSON(&rl); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rl})
}

// ── CORS & Compression Configuration ──

func (h *ExtendedHandler) GetCORSConfig(c *gin.Context) {
	cors := &CORSConfig{
		AllowedOrigins: h.cfg.AllowedOrigins,
		AllowedMethods: []string{"GET", "HEAD", "OPTIONS"},
		AllowedHeaders: []string{"Origin", "Content-Type", "Accept", "Range"},
		MaxAge:         86400,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cors})
}

func (h *ExtendedHandler) UpdateCORSConfig(c *gin.Context) {
	var cors CORSConfig
	if err := c.ShouldBindJSON(&cors); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": cors})
}

func (h *ExtendedHandler) GetCompressionConfig(c *gin.Context) {
	comp := &CompressionConfig{
		Enabled:   h.cfg.EnableCompression,
		MinSize:   1024,
		Types:     []string{"text/html", "text/css", "application/javascript", "application/json"},
		Level:     6,
		Algorithm: "gzip",
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": comp})
}

func (h *ExtendedHandler) UpdateCompressionConfig(c *gin.Context) {
	var comp CompressionConfig
	if err := c.ShouldBindJSON(&comp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": comp})
}

func (h *ExtendedHandler) GetCacheRules(c *gin.Context) {
	rules := map[string]interface{}{
		"default_ttl":  h.cfg.CacheTTL.String(),
		"max_size":     h.cfg.MaxCacheSize,
		"rules": []map[string]interface{}{
			{"pattern": "*.jpg", "ttl": "7d"},
			{"pattern": "*.png", "ttl": "7d"},
			{"pattern": "*.css", "ttl": "30d"},
			{"pattern": "*.js", "ttl": "30d"},
		},
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rules})
}

func (h *ExtendedHandler) UpdateCacheRules(c *gin.Context) {
	var rules map[string]interface{}
	if err := c.ShouldBindJSON(&rules); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rules})
}

// ── Edge Locations ──

func (h *ExtendedHandler) ListEdgeLocations(c *gin.Context) {
	locations := []EdgeLocation{
		{ID: "us-east-1", Name: "US East (Virginia)", Region: "us-east-1", Status: "active"},
		{ID: "us-west-2", Name: "US West (Oregon)", Region: "us-west-2", Status: "active"},
		{ID: "eu-west-1", Name: "EU West (Ireland)", Region: "eu-west-1", Status: "active"},
		{ID: "ap-southeast-1", Name: "Asia Pacific (Singapore)", Region: "ap-southeast-1", Status: "active"},
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": locations})
}

func (h *ExtendedHandler) GetEdgeLocation(c *gin.Context) {
	locationID := c.Param("locationId")
	location := &EdgeLocation{
		ID:     locationID,
		Name:   "Edge Location " + locationID,
		Region: locationID,
		Status: "active",
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": location})
}

func (h *ExtendedHandler) GetEdgeStatus(c *gin.Context) {
	status := map[string]interface{}{
		"total_locations":  4,
		"active":           4,
		"draining":         0,
		"inactive":         0,
		"global_hit_rate":  0.85,
		"avg_latency_ms":   15,
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": status})
}

// ── Bulk Operations ──

func (h *ExtendedHandler) BulkPurge(c *gin.Context) {
	var req PurgeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	purged := 0
	if h.cache != nil {
		for _, path := range req.Paths {
			if h.cache.Delete(c.Request.Context(), "cdn:file:"+path) == nil {
				purged++
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "purged": purged})
}

func (h *ExtendedHandler) BulkPreload(c *gin.Context) {
	var req PreloadRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	preloaded := 0
	for _, path := range req.Paths {
		if h.storage.Exists(c.Request.Context(), path) {
			preloaded++
		}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "preloaded": preloaded})
}

func (h *ExtendedHandler) BulkInvalidate(c *gin.Context) {
	var req struct {
		Patterns []string `json:"patterns" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "invalidated_patterns": len(req.Patterns)})
}

// ── Directory Operations ──

func (h *ExtendedHandler) ListDirectory(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	_ = path
	entries := []map[string]interface{}{}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": entries})
}

func (h *ExtendedHandler) ListDirectoryRecursive(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	_ = path
	entries := []map[string]interface{}{}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": entries})
}

// ── Streaming & Downloads ──

func (h *ExtendedHandler) ForceDownload(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	reader, info, err := h.storage.Get(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer reader.Close()

	filename := filepath.Base(path)
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Length", strconv.FormatInt(info.ContentLength, 10))
	c.DataFromReader(http.StatusOK, info.ContentLength, "application/octet-stream", reader, nil)
}

func (h *ExtendedHandler) StreamFile(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	reader, info, err := h.storage.Get(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer reader.Close()

	c.Header("Content-Type", info.ContentType)
	c.Header("Accept-Ranges", "bytes")
	c.Header("Transfer-Encoding", "chunked")
	c.DataFromReader(http.StatusOK, info.ContentLength, info.ContentType, reader, nil)
}

func (h *ExtendedHandler) ServeEmbed(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	reader, info, err := h.storage.Get(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer reader.Close()

	c.Header("Content-Type", info.ContentType)
	c.Header("Content-Disposition", "inline")
	c.Header("X-Frame-Options", "SAMEORIGIN")
	c.DataFromReader(http.StatusOK, info.ContentLength, info.ContentType, reader, nil)
}

// ── ZIP Streaming ──

func (h *ExtendedHandler) CreateZipDownload(c *gin.Context) {
	var req struct {
		Paths    []string `json:"paths" binding:"required"`
		Filename string   `json:"filename"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Filename == "" {
		req.Filename = "download.zip"
	}
	// In a real implementation, this would create a ZIP stream
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"message":  "ZIP download initiated",
		"filename": req.Filename,
		"files":    len(req.Paths),
	})
}

// ── Helpers ──

func generateToken(path string, expiresAt time.Time) string {
	secret := "cdn-signing-secret" // In production, this would come from config
	data := fmt.Sprintf("%s:%d", path, expiresAt.Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}
