package gin

import (
	"fmt"

	"github.com/Fischlvor/go-ratelimiter"
	"github.com/gin-gonic/gin"
)

// Limiter 限流器接口
type Limiter interface {
	Check(path, method, ip, userID string) (*ratelimiter.Result, error)
}

// Middleware Gin限流中间件
type Middleware struct {
	Limiter    Limiter
	OnError    func(*gin.Context, error)
	OnExceeded func(*gin.Context, *ratelimiter.Result)
	KeyGetter  func(*gin.Context) (path, method, ip, userID string)
}

// NewMiddleware 创建Gin中间件
func NewMiddleware(limiter Limiter, options ...Option) gin.HandlerFunc {
	m := &Middleware{
		Limiter:    limiter,
		OnError:    DefaultErrorHandler,
		OnExceeded: DefaultExceededHandler,
		KeyGetter:  DefaultKeyGetter,
	}

	for _, opt := range options {
		opt(m)
	}

	return func(c *gin.Context) {
		m.Handle(c)
	}
}

// Handle 处理请求
func (m *Middleware) Handle(c *gin.Context) {
	path, method, ip, userID := m.KeyGetter(c)

	result, err := m.Limiter.Check(path, method, ip, userID)
	if err != nil {
		m.OnError(c, err)
		return
	}

	// 设置限流响应头
	c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", result.Limit))
	c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", result.Remaining))
	c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", result.Reset))

	if !result.Allowed {
		c.Header("Retry-After", fmt.Sprintf("%d", result.RetryAfter))
		m.OnExceeded(c, result)
		return
	}

	c.Next()
}

// Option 中间件选项
type Option func(*Middleware)

// WithErrorHandler 自定义错误处理
func WithErrorHandler(handler func(*gin.Context, error)) Option {
	return func(m *Middleware) {
		m.OnError = handler
	}
}

// WithExceededHandler 自定义限流超出处理
func WithExceededHandler(handler func(*gin.Context, *ratelimiter.Result)) Option {
	return func(m *Middleware) {
		m.OnExceeded = handler
	}
}

// WithKeyGetter 自定义key获取
func WithKeyGetter(getter func(*gin.Context) (path, method, ip, userID string)) Option {
	return func(m *Middleware) {
		m.KeyGetter = getter
	}
}

// DefaultErrorHandler 默认错误处理
func DefaultErrorHandler(c *gin.Context, err error) {
	c.JSON(500, gin.H{
		"error": "限流检查失败",
		"msg":   err.Error(),
	})
	c.Abort()
}

// DefaultExceededHandler 默认限流超出处理
func DefaultExceededHandler(c *gin.Context, result *ratelimiter.Result) {
	c.JSON(429, gin.H{
		"error":     "请求过于频繁",
		"limit":     result.Limit,
		"remaining": result.Remaining,
		"reset":     result.Reset,
	})
	c.Abort()
}

// DefaultKeyGetter 默认key获取
func DefaultKeyGetter(c *gin.Context) (path, method, ip, userID string) {
	return c.Request.URL.Path, c.Request.Method, c.ClientIP(), c.GetString("user_id")
}
