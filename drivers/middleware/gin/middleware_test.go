package gin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Fischlvor/go-ratelimiter"
	"github.com/gin-gonic/gin"
)

// MockLimiter 模拟限流器
type MockLimiter struct {
	checkFunc func(path, method, ip, userID string) (*ratelimiter.Result, error)
}

func (m *MockLimiter) Check(path, method, ip, userID string) (*ratelimiter.Result, error) {
	if m.checkFunc != nil {
		return m.checkFunc(path, method, ip, userID)
	}
	return &ratelimiter.Result{Allowed: true}, nil
}

func TestMiddleware_Allow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLimiter := &MockLimiter{
		checkFunc: func(path, method, ip, userID string) (*ratelimiter.Result, error) {
			return &ratelimiter.Result{
				Allowed:    true,
				Limit:      100,
				Remaining:  99,
				Reset:      time.Now().Unix() + 60,
				RetryAfter: 0,
			}, nil
		},
	}

	r := gin.New()
	r.Use(NewMiddleware(mockLimiter))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("期望状态码 200, 得到 %d", w.Code)
	}

	// 检查限流响应头
	if w.Header().Get("X-RateLimit-Limit") != "100" {
		t.Errorf("X-RateLimit-Limit = %s, want 100", w.Header().Get("X-RateLimit-Limit"))
	}
	if w.Header().Get("X-RateLimit-Remaining") != "99" {
		t.Errorf("X-RateLimit-Remaining = %s, want 99", w.Header().Get("X-RateLimit-Remaining"))
	}
}

func TestMiddleware_Exceeded(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLimiter := &MockLimiter{
		checkFunc: func(path, method, ip, userID string) (*ratelimiter.Result, error) {
			return &ratelimiter.Result{
				Allowed:    false,
				Limit:      100,
				Remaining:  0,
				Reset:      time.Now().Unix() + 60,
				RetryAfter: 60,
			}, nil
		},
	}

	r := gin.New()
	r.Use(NewMiddleware(mockLimiter))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if w.Code != 429 {
		t.Errorf("期望状态码 429, 得到 %d", w.Code)
	}

	// 检查Retry-After响应头
	if w.Header().Get("Retry-After") != "60" {
		t.Errorf("Retry-After = %s, want 60", w.Header().Get("Retry-After"))
	}
}

func TestMiddleware_CustomErrorHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLimiter := &MockLimiter{
		checkFunc: func(path, method, ip, userID string) (*ratelimiter.Result, error) {
			return nil, fmt.Errorf("配置错误")
		},
	}

	customErrorCalled := false
	r := gin.New()
	r.Use(NewMiddleware(mockLimiter,
		WithErrorHandler(func(c *gin.Context, err error) {
			customErrorCalled = true
			c.JSON(503, gin.H{"custom_error": err.Error()})
			c.Abort()
		}),
	))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if !customErrorCalled {
		t.Error("自定义错误处理器未被调用")
	}

	if w.Code != 503 {
		t.Errorf("期望状态码 503, 得到 %d", w.Code)
	}
}

func TestMiddleware_CustomExceededHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockLimiter := &MockLimiter{
		checkFunc: func(path, method, ip, userID string) (*ratelimiter.Result, error) {
			return &ratelimiter.Result{
				Allowed:    false,
				Limit:      10,
				Remaining:  0,
				Reset:      time.Now().Unix() + 30,
				RetryAfter: 30,
			}, nil
		},
	}

	customExceededCalled := false
	r := gin.New()
	r.Use(NewMiddleware(mockLimiter,
		WithExceededHandler(func(c *gin.Context, result *ratelimiter.Result) {
			customExceededCalled = true
			c.JSON(429, gin.H{
				"custom_message": "太快了",
				"retry":          result.RetryAfter,
			})
			c.Abort()
		}),
	))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if !customExceededCalled {
		t.Error("自定义超出处理器未被调用")
	}

	if w.Code != 429 {
		t.Errorf("期望状态码 429, 得到 %d", w.Code)
	}
}

func TestMiddleware_CustomKeyGetter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var capturedUserID string
	mockLimiter := &MockLimiter{
		checkFunc: func(path, method, ip, userID string) (*ratelimiter.Result, error) {
			capturedUserID = userID
			return &ratelimiter.Result{Allowed: true}, nil
		},
	}

	r := gin.New()
	r.Use(NewMiddleware(mockLimiter,
		WithKeyGetter(func(c *gin.Context) (path, method, ip, userID string) {
			return c.Request.URL.Path, c.Request.Method, c.ClientIP(), "custom_user_123"
		}),
	))
	r.GET("/test", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "success"})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)

	if capturedUserID != "custom_user_123" {
		t.Errorf("capturedUserID = %s, want custom_user_123", capturedUserID)
	}
}

func TestDefaultKeyGetter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		c.Set("user_id", "test_user")
		path, method, ip, userID := DefaultKeyGetter(c)

		if path != "/test" {
			t.Errorf("path = %s, want /test", path)
		}
		if method != "GET" {
			t.Errorf("method = %s, want GET", method)
		}
		// IP可能为空（在测试环境中）
		t.Logf("IP: %s", ip)
		if userID != "test_user" {
			t.Errorf("userID = %s, want test_user", userID)
		}

		c.JSON(200, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	r.ServeHTTP(w, req)
}

func BenchmarkMiddleware(b *testing.B) {
	gin.SetMode(gin.ReleaseMode)

	mockLimiter := &MockLimiter{
		checkFunc: func(path, method, ip, userID string) (*ratelimiter.Result, error) {
			return &ratelimiter.Result{
				Allowed:   true,
				Limit:     1000,
				Remaining: 999,
			}, nil
		},
	}

	r := gin.New()
	r.Use(NewMiddleware(mockLimiter))
	r.GET("/test", func(c *gin.Context) {
		c.Status(200)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.ServeHTTP(w, req)
	}
}
