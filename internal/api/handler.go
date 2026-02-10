package api

import (
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"cdn-service/internal/cache"
	"cdn-service/internal/config"
	"cdn-service/internal/storage"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	storage storage.Storage
	cache   cache.Cache
	cfg     *config.Config
}

func RegisterRoutes(router *gin.Engine, storage storage.Storage, cacheBackend cache.Cache, cfg *config.Config) {
	h := &Handler{
		storage: storage,
		cache:   cacheBackend,
		cfg:     cfg,
	}

	// Apply CORS middleware
	router.Use(h.CORSMiddleware())

	// Health endpoints
	router.GET("/health", h.Health)
	router.GET("/health/ready", h.HealthReady)
	router.GET("/health/live", h.HealthLive)

	// File serving
	router.GET("/files/*path", h.ServeFile)
	router.HEAD("/files/*path", h.HeadFile)

	// Thumbnails
	router.GET("/thumbnails/*path", h.ServeThumbnail)

	// Extended features
	RegisterExtendedRoutes(router, storage, cacheBackend, cfg)
}

func (h *Handler) CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept, Range")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (h *Handler) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "cdn-service",
	})
}

func (h *Handler) HealthReady(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"ready": true})
}

func (h *Handler) HealthLive(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"live": true})
}

func (h *Handler) ServeFile(c *gin.Context) {
	path := c.Param("path")
	if path == "" || path == "/" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Check for range request
	rangeHeader := c.GetHeader("Range")
	if rangeHeader != "" && h.cfg.EnableRangeRequests {
		h.serveRangeRequest(c, path, rangeHeader)
		return
	}

	// Get file from storage
	reader, info, err := h.storage.Get(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}
	defer reader.Close()

	// Set headers
	h.setFileHeaders(c, info, path)

	// Stream file
	c.DataFromReader(http.StatusOK, info.ContentLength, info.ContentType, reader, nil)
}

func (h *Handler) HeadFile(c *gin.Context) {
	path := c.Param("path")
	if path == "" || path == "/" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	path = strings.TrimPrefix(path, "/")

	info, err := h.storage.Head(c.Request.Context(), path)
	if err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	h.setFileHeaders(c, info, path)
	c.Status(http.StatusOK)
}

func (h *Handler) serveRangeRequest(c *gin.Context, path string, rangeHeader string) {
	// Parse range header
	start, end, err := parseRangeHeader(rangeHeader)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid range"})
		return
	}

	// Get file info first
	info, err := h.storage.Head(c.Request.Context(), path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
		return
	}

	// Adjust end if not specified
	if end == -1 {
		end = info.ContentLength - 1
	}

	// Validate range
	if start > end || start >= info.ContentLength {
		c.Header("Content-Range", fmt.Sprintf("bytes */%d", info.ContentLength))
		c.Status(http.StatusRequestedRangeNotSatisfiable)
		return
	}

	// Get range from storage
	reader, _, err := h.storage.GetRange(c.Request.Context(), path, start, end)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}
	defer reader.Close()

	// Set headers for partial content
	c.Header("Content-Type", info.ContentType)
	c.Header("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, info.ContentLength))
	c.Header("Accept-Ranges", "bytes")
	c.Header("Content-Length", strconv.FormatInt(end-start+1, 10))

	c.Status(http.StatusPartialContent)
	io.Copy(c.Writer, reader)
}

func (h *Handler) ServeThumbnail(c *gin.Context) {
	path := c.Param("path")
	if path == "" || path == "/" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Path required"})
		return
	}

	path = strings.TrimPrefix(path, "/")
	thumbnailPath := "thumbnails/" + path

	// Try to get thumbnail
	reader, info, err := h.storage.Get(c.Request.Context(), thumbnailPath)
	if err != nil {
		// Fall back to original file
		reader, info, err = h.storage.Get(c.Request.Context(), path)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "File not found"})
			return
		}
	}
	defer reader.Close()

	h.setFileHeaders(c, info, path)
	c.DataFromReader(http.StatusOK, info.ContentLength, info.ContentType, reader, nil)
}

func (h *Handler) setFileHeaders(c *gin.Context, info *storage.FileInfo, path string) {
	c.Header("Content-Type", info.ContentType)
	c.Header("Content-Length", strconv.FormatInt(info.ContentLength, 10))
	c.Header("Accept-Ranges", "bytes")

	if info.ETag != "" {
		c.Header("ETag", info.ETag)
	}
	if info.LastModified != "" {
		c.Header("Last-Modified", info.LastModified)
	}

	// Cache control
	c.Header("Cache-Control", fmt.Sprintf("public, max-age=%d", int(h.cfg.CacheTTL.Seconds())))

	// Content disposition for downloads
	if c.Query("download") == "true" {
		filename := filepath.Base(path)
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	}
}

func parseRangeHeader(rangeHeader string) (int64, int64, error) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, 0, fmt.Errorf("invalid range format")
	}

	rangeParts := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(rangeParts, "-")

	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid range format")
	}

	var start, end int64 = 0, -1

	if parts[0] != "" {
		var err error
		start, err = strconv.ParseInt(parts[0], 10, 64)
		if err != nil {
			return 0, 0, err
		}
	}

	if parts[1] != "" {
		var err error
		end, err = strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, err
		}
	}

	return start, end, nil
}
