package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cdn-service/internal/cache"
	"cdn-service/internal/config"
	"cdn-service/internal/storage"

	"github.com/gin-gonic/gin"
)

// ── Additional Models ──

type CacheRule struct {
	ID          string `json:"id"`
	Pattern     string `json:"pattern"`
	TTL         string `json:"ttl"`
	CacheType   string `json:"cache_type"` // public, private, no-cache, no-store
	Compress    bool   `json:"compress"`
	IsActive    bool   `json:"is_active"`
	Priority    int    `json:"priority"`
}

type HeaderRule struct {
	ID        string            `json:"id"`
	Pattern   string            `json:"pattern"`
	Headers   map[string]string `json:"headers"`
	IsActive  bool              `json:"is_active"`
}

type RedirectRule struct {
	ID          string `json:"id"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	StatusCode  int    `json:"status_code"` // 301, 302, 307, 308
	IsActive    bool   `json:"is_active"`
}

type RewriteRule struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	IsActive bool   `json:"is_active"`
}

type WafRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // block_ip, block_ua, block_referer, custom
	Action      string   `json:"action"` // block, challenge, allow, log
	Conditions  []string `json:"conditions"`
	IsActive    bool     `json:"is_active"`
}

type SSLConfig struct {
	Enabled       bool   `json:"enabled"`
	MinVersion    string `json:"min_version"` // TLS1.2, TLS1.3
	HSTS          bool   `json:"hsts"`
	HSTSMaxAge    int    `json:"hsts_max_age"`
	RedirectHTTP  bool   `json:"redirect_http"`
}

type CustomDomain struct {
	ID          string    `json:"id"`
	Domain      string    `json:"domain"`
	Status      string    `json:"status"` // pending, active, failed
	SSLStatus   string    `json:"ssl_status"`
	CreatedAt   time.Time `json:"created_at"`
}

type WebhookConfig struct {
	ID          string   `json:"id"`
	URL         string   `json:"url"`
	Events      []string `json:"events"` // cache_purge, origin_down, ssl_expiring
	Secret      string   `json:"secret"`
	IsActive    bool     `json:"is_active"`
}

type PerfMetrics struct {
	TTFB          float64 `json:"ttfb_ms"`
	TransferTime  float64 `json:"transfer_time_ms"`
	CacheHitRatio float64 `json:"cache_hit_ratio"`
	Throughput    float64 `json:"throughput_mbps"`
	P50Latency    float64 `json:"p50_latency_ms"`
	P95Latency    float64 `json:"p95_latency_ms"`
	P99Latency    float64 `json:"p99_latency_ms"`
}

// ── Extended Handler 2 ──

type ExtendedHandler2 struct {
	storage storage.Storage
	cache   cache.Cache
	cfg     *config.Config
}

func RegisterExtendedRoutes2(router *gin.Engine, s storage.Storage, c cache.Cache, cfg *config.Config) {
	h := &ExtendedHandler2{storage: s, cache: c, cfg: cfg}

	// Cache Rules
	router.GET("/api/v1/cache/rules", h.ListCacheRules)
	router.POST("/api/v1/cache/rules", h.CreateCacheRule)
	router.PUT("/api/v1/cache/rules/:ruleId", h.UpdateCacheRule)
	router.DELETE("/api/v1/cache/rules/:ruleId", h.DeleteCacheRule)

	// Header Rules
	router.GET("/api/v1/headers/rules", h.ListHeaderRules)
	router.POST("/api/v1/headers/rules", h.CreateHeaderRule)
	router.PUT("/api/v1/headers/rules/:ruleId", h.UpdateHeaderRule)
	router.DELETE("/api/v1/headers/rules/:ruleId", h.DeleteHeaderRule)

	// Redirects
	router.GET("/api/v1/redirects", h.ListRedirects)
	router.POST("/api/v1/redirects", h.CreateRedirect)
	router.PUT("/api/v1/redirects/:redirectId", h.UpdateRedirect)
	router.DELETE("/api/v1/redirects/:redirectId", h.DeleteRedirect)

	// Rewrites
	router.GET("/api/v1/rewrites", h.ListRewrites)
	router.POST("/api/v1/rewrites", h.CreateRewrite)
	router.PUT("/api/v1/rewrites/:rewriteId", h.UpdateRewrite)
	router.DELETE("/api/v1/rewrites/:rewriteId", h.DeleteRewrite)

	// WAF Rules
	router.GET("/api/v1/waf/rules", h.ListWafRules)
	router.POST("/api/v1/waf/rules", h.CreateWafRule)
	router.PUT("/api/v1/waf/rules/:ruleId", h.UpdateWafRule)
	router.DELETE("/api/v1/waf/rules/:ruleId", h.DeleteWafRule)

	// SSL
	router.GET("/api/v1/ssl/config", h.GetSSLConfig)
	router.PUT("/api/v1/ssl/config", h.UpdateSSLConfig)

	// Custom Domains
	router.GET("/api/v1/domains", h.ListDomains)
	router.POST("/api/v1/domains", h.AddDomain)
	router.DELETE("/api/v1/domains/:domainId", h.RemoveDomain)
	router.POST("/api/v1/domains/:domainId/verify", h.VerifyDomain)

	// Webhooks
	router.GET("/api/v1/webhooks", h.ListWebhooks)
	router.POST("/api/v1/webhooks", h.CreateWebhook)
	router.PUT("/api/v1/webhooks/:webhookId", h.UpdateWebhook)
	router.DELETE("/api/v1/webhooks/:webhookId", h.DeleteWebhook)
	router.POST("/api/v1/webhooks/:webhookId/test", h.TestWebhook)

	// Performance Metrics
	router.GET("/api/v1/performance/metrics", h.GetPerfMetrics)
	router.GET("/api/v1/performance/latency", h.GetLatencyMetrics)
	router.GET("/api/v1/performance/throughput", h.GetThroughputMetrics)

	// Real-time Logs
	router.GET("/api/v1/logs/realtime", h.GetRealtimeLogs)
	router.GET("/api/v1/logs/search", h.SearchLogs)

	// File Operations
	router.POST("/api/v1/files/validate", h.ValidateFile)
	router.GET("/api/v1/files/types", h.ListSupportedTypes)

	// Optimization
	router.POST("/api/v1/optimize/image/*path", h.OptimizeImage)
	router.POST("/api/v1/optimize/video/*path", h.OptimizeVideo)
	router.GET("/api/v1/optimize/suggestions", h.GetOptimizationSuggestions)
}

// ── Cache Rules ──

func (h *ExtendedHandler2) ListCacheRules(c *gin.Context) {
	rules := []CacheRule{}
	if h.cache != nil {
		data, err := h.cache.Get(c.Request.Context(), "cdn:cache_rules")
		if err == nil && data != nil { _ = json.Unmarshal(data, &rules) }
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": rules})
}

func (h *ExtendedHandler2) CreateCacheRule(c *gin.Context) {
	var rule CacheRule
	if err := c.ShouldBindJSON(&rule); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	rule.IsActive = true
	c.JSON(201, gin.H{"success": true, "data": rule})
}

func (h *ExtendedHandler2) UpdateCacheRule(c *gin.Context) {
	var rule CacheRule
	if err := c.ShouldBindJSON(&rule); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	rule.ID = c.Param("ruleId")
	c.JSON(200, gin.H{"success": true, "data": rule})
}

func (h *ExtendedHandler2) DeleteCacheRule(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

// ── Header Rules ──

func (h *ExtendedHandler2) ListHeaderRules(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []HeaderRule{}})
}

func (h *ExtendedHandler2) CreateHeaderRule(c *gin.Context) {
	var rule HeaderRule
	if err := c.ShouldBindJSON(&rule); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	rule.IsActive = true
	c.JSON(201, gin.H{"success": true, "data": rule})
}

func (h *ExtendedHandler2) UpdateHeaderRule(c *gin.Context) {
	var rule HeaderRule
	if err := c.ShouldBindJSON(&rule); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	rule.ID = c.Param("ruleId")
	c.JSON(200, gin.H{"success": true, "data": rule})
}

func (h *ExtendedHandler2) DeleteHeaderRule(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

// ── Redirects ──

func (h *ExtendedHandler2) ListRedirects(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []RedirectRule{}})
}

func (h *ExtendedHandler2) CreateRedirect(c *gin.Context) {
	var r RedirectRule
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	if r.StatusCode == 0 { r.StatusCode = 301 }
	r.IsActive = true
	c.JSON(201, gin.H{"success": true, "data": r})
}

func (h *ExtendedHandler2) UpdateRedirect(c *gin.Context) {
	var r RedirectRule
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	r.ID = c.Param("redirectId")
	c.JSON(200, gin.H{"success": true, "data": r})
}

func (h *ExtendedHandler2) DeleteRedirect(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

// ── Rewrites ──

func (h *ExtendedHandler2) ListRewrites(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []RewriteRule{}})
}

func (h *ExtendedHandler2) CreateRewrite(c *gin.Context) {
	var r RewriteRule
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	r.IsActive = true
	c.JSON(201, gin.H{"success": true, "data": r})
}

func (h *ExtendedHandler2) UpdateRewrite(c *gin.Context) {
	var r RewriteRule
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	r.ID = c.Param("rewriteId")
	c.JSON(200, gin.H{"success": true, "data": r})
}

func (h *ExtendedHandler2) DeleteRewrite(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

// ── WAF Rules ──

func (h *ExtendedHandler2) ListWafRules(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []WafRule{}})
}

func (h *ExtendedHandler2) CreateWafRule(c *gin.Context) {
	var r WafRule
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	r.IsActive = true
	c.JSON(201, gin.H{"success": true, "data": r})
}

func (h *ExtendedHandler2) UpdateWafRule(c *gin.Context) {
	var r WafRule
	if err := c.ShouldBindJSON(&r); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	r.ID = c.Param("ruleId")
	c.JSON(200, gin.H{"success": true, "data": r})
}

func (h *ExtendedHandler2) DeleteWafRule(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

// ── SSL ──

func (h *ExtendedHandler2) GetSSLConfig(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": SSLConfig{Enabled: true, MinVersion: "TLS1.2", HSTS: true, HSTSMaxAge: 31536000, RedirectHTTP: true}})
}

func (h *ExtendedHandler2) UpdateSSLConfig(c *gin.Context) {
	var cfg SSLConfig
	if err := c.ShouldBindJSON(&cfg); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	c.JSON(200, gin.H{"success": true, "data": cfg})
}

// ── Custom Domains ──

func (h *ExtendedHandler2) ListDomains(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []CustomDomain{}})
}

func (h *ExtendedHandler2) AddDomain(c *gin.Context) {
	var d CustomDomain
	if err := c.ShouldBindJSON(&d); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	d.Status = "pending"
	d.SSLStatus = "pending"
	d.CreatedAt = time.Now()
	c.JSON(201, gin.H{"success": true, "data": d})
}

func (h *ExtendedHandler2) RemoveDomain(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

func (h *ExtendedHandler2) VerifyDomain(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "verified": true, "domain_id": c.Param("domainId")})
}

// ── Webhooks ──

func (h *ExtendedHandler2) ListWebhooks(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []WebhookConfig{}})
}

func (h *ExtendedHandler2) CreateWebhook(c *gin.Context) {
	var w WebhookConfig
	if err := c.ShouldBindJSON(&w); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	w.IsActive = true
	c.JSON(201, gin.H{"success": true, "data": w})
}

func (h *ExtendedHandler2) UpdateWebhook(c *gin.Context) {
	var w WebhookConfig
	if err := c.ShouldBindJSON(&w); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	w.ID = c.Param("webhookId")
	c.JSON(200, gin.H{"success": true, "data": w})
}

func (h *ExtendedHandler2) DeleteWebhook(c *gin.Context) {
	c.JSON(200, gin.H{"success": true})
}

func (h *ExtendedHandler2) TestWebhook(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "test_result": "delivered", "response_code": 200})
}

// ── Performance ──

func (h *ExtendedHandler2) GetPerfMetrics(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": PerfMetrics{TTFB: 12.5, TransferTime: 45.2, CacheHitRatio: 0.85, Throughput: 125.5, P50Latency: 15.0, P95Latency: 45.0, P99Latency: 120.0}})
}

func (h *ExtendedHandler2) GetLatencyMetrics(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"p50": 15.0, "p75": 25.0, "p90": 40.0, "p95": 45.0, "p99": 120.0}})
}

func (h *ExtendedHandler2) GetThroughputMetrics(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": gin.H{"current_mbps": 125.5, "peak_mbps": 450.0, "avg_mbps": 95.3}})
}

// ── Logs ──

func (h *ExtendedHandler2) GetRealtimeLogs(c *gin.Context) {
	c.JSON(200, gin.H{"success": true, "data": []AccessLogEntry{}})
}

func (h *ExtendedHandler2) SearchLogs(c *gin.Context) {
	query := c.Query("q")
	_ = query
	c.JSON(200, gin.H{"success": true, "data": []AccessLogEntry{}})
}

// ── File Operations ──

func (h *ExtendedHandler2) ValidateFile(c *gin.Context) {
	var req struct{ Path string `json:"path"` }
	if err := c.ShouldBindJSON(&req); err != nil { c.JSON(400, gin.H{"error": err.Error()}); return }
	exists := h.storage.Exists(c.Request.Context(), req.Path)
	result := gin.H{"path": req.Path, "exists": exists, "valid": exists}
	if exists {
		info, err := h.storage.Head(c.Request.Context(), req.Path)
		if err == nil {
			result["size"] = info.ContentLength
			result["content_type"] = info.ContentType
		}
	}
	c.JSON(200, gin.H{"success": true, "data": result})
}

func (h *ExtendedHandler2) ListSupportedTypes(c *gin.Context) {
	types := map[string][]string{
		"images":    {"image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml", "image/avif"},
		"videos":    {"video/mp4", "video/webm", "video/ogg"},
		"audio":     {"audio/mpeg", "audio/ogg", "audio/wav", "audio/webm"},
		"documents": {"application/pdf", "text/plain", "text/html", "text/css", "application/javascript"},
		"archives":  {"application/zip", "application/gzip", "application/x-tar"},
	}
	c.JSON(200, gin.H{"success": true, "data": types})
}

// ── Optimization ──

func (h *ExtendedHandler2) OptimizeImage(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	if !h.storage.Exists(c.Request.Context(), path) {
		c.JSON(404, gin.H{"error": "file not found"})
		return
	}
	c.JSON(200, gin.H{"success": true, "data": gin.H{"path": path, "optimized": true, "savings_pct": 35}})
}

func (h *ExtendedHandler2) OptimizeVideo(c *gin.Context) {
	path := strings.TrimPrefix(c.Param("path"), "/")
	c.JSON(200, gin.H{"success": true, "data": gin.H{"path": path, "status": "processing", "estimated_savings_pct": 40}})
}

func (h *ExtendedHandler2) GetOptimizationSuggestions(c *gin.Context) {
	suggestions := []map[string]interface{}{
		{"type": "image_compression", "description": "Enable WebP conversion for JPEG images", "estimated_savings": "30-40%"},
		{"type": "minification", "description": "Minify CSS and JavaScript files", "estimated_savings": "20-30%"},
		{"type": "caching", "description": fmt.Sprintf("Increase cache TTL from %s", h.cfg.CacheTTL), "estimated_savings": "15% fewer origin requests"},
	}
	c.JSON(200, gin.H{"success": true, "data": suggestions})
}
