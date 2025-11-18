package ratelimiter

import (
	"testing"
	"time"
)

// MockStore 用于测试的模拟存储
type MockStore struct {
	data map[string]int64
	ttl  map[string]time.Duration
}

func NewMockStore() *MockStore {
	return &MockStore{
		data: make(map[string]int64),
		ttl:  make(map[string]time.Duration),
	}
}

func (m *MockStore) Get(key string) (int64, error) {
	return m.data[key], nil
}

func (m *MockStore) Incr(key string) (int64, error) {
	m.data[key]++
	return m.data[key], nil
}

func (m *MockStore) IncrBy(key string, value int64) (int64, error) {
	m.data[key] += value
	return m.data[key], nil
}

func (m *MockStore) Expire(key string, expiration time.Duration) error {
	m.ttl[key] = expiration
	return nil
}

func (m *MockStore) TTL(key string) (time.Duration, error) {
	if ttl, ok := m.ttl[key]; ok {
		return ttl, nil
	}
	return -1, nil
}

func (m *MockStore) ZAdd(key string, score float64, member string) error {
	return nil
}

func (m *MockStore) ZRemRangeByScore(key string, min, max float64) error {
	return nil
}

func (m *MockStore) ZCount(key string, min, max float64) (int64, error) {
	return 0, nil
}

func (m *MockStore) Eval(script string, keys []string, args ...interface{}) (interface{}, error) {
	return nil, nil
}

func TestNewFromConfig(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Whitelist: WhitelistConfig{
			IPs:   []string{"127.0.0.1"},
			Users: []string{"admin"},
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	if limiter == nil {
		t.Fatal("limiter should not be nil")
	}

	// 检查白名单
	if !limiter.whitelistIPs["127.0.0.1"] {
		t.Error("127.0.0.1 should be in whitelist")
	}
	if !limiter.whitelistUsers["admin"] {
		t.Error("admin should be in whitelist")
	}
}

func TestLimiter_Check_Whitelist(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
		Whitelist: WhitelistConfig{
			IPs:   []string{"192.168.1.1"},
			Users: []string{"vip_user"},
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	// 测试IP白名单
	result, err := limiter.Check("/api/test", "GET", "192.168.1.1", "")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Allowed {
		t.Error("白名单IP应该被允许")
	}

	// 测试用户白名单
	result, err = limiter.Check("/api/test", "GET", "1.2.3.4", "vip_user")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Allowed {
		t.Error("白名单用户应该被允许")
	}
}

func TestLimiter_BuildKey(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	tests := []struct {
		name    string
		rule    *Rule
		path    string
		ip      string
		userID  string
		wantKey string
	}{
		{
			name: "按IP限流",
			rule: &Rule{
				Name: "test_rule",
				By:   LimitByIP,
			},
			path:    "/api/test",
			ip:      "1.2.3.4",
			userID:  "",
			wantKey: "test_rule:ip:1.2.3.4",
		},
		{
			name: "按用户限流",
			rule: &Rule{
				Name: "test_rule",
				By:   LimitByUser,
			},
			path:    "/api/test",
			ip:      "1.2.3.4",
			userID:  "user123",
			wantKey: "test_rule:user:user123",
		},
		{
			name: "全局限流",
			rule: &Rule{
				Name: "test_rule",
				By:   LimitByGlobal,
			},
			path:    "/api/test",
			ip:      "1.2.3.4",
			userID:  "user123",
			wantKey: "test_rule:global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := limiter.buildKey(tt.rule, tt.path, tt.ip, tt.userID)
			if key != tt.wantKey {
				t.Errorf("buildKey() = %v, want %v", key, tt.wantKey)
			}
		})
	}
}

func TestLimiter_CheckRule(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	rule := &Rule{
		Name:      "test",
		Algorithm: AlgorithmFixedWindow,
		Limit:     5,
		Window:    time.Minute,
		By:        LimitByIP,
	}

	// 发送5个请求，都应该被允许
	for i := 0; i < 5; i++ {
		result, err := limiter.checkRule(rule, "/api/test", "GET", "1.2.3.4", "")
		if err != nil {
			t.Fatalf("checkRule() error = %v", err)
		}
		if !result.Allowed {
			t.Errorf("请求 %d 应该被允许", i+1)
		}
	}

	// 第6个请求应该被拒绝
	result, err := limiter.checkRule(rule, "/api/test", "GET", "1.2.3.4", "")
	if err != nil {
		t.Fatalf("checkRule() error = %v", err)
	}
	if result.Allowed {
		t.Error("第6个请求应该被拒绝")
	}
	if result.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0", result.Remaining)
	}
}

func BenchmarkLimiter_Check(b *testing.B) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
		Global: &GlobalConfig{
			Algorithm: "fixed_window",
			Limit:     1000000,
			Window:    "1s",
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := limiter.Check("/api/test", "GET", "1.2.3.4", "")
		if err != nil {
			b.Fatal(err)
		}
	}
}
