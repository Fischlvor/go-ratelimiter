package algorithm

import (
	"testing"
	"time"
)

// MockStore 模拟存储
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

func (m *MockStore) Set(key string, value int64) error {
	m.data[key] = value
	return nil
}

func (m *MockStore) Del(key string) error {
	delete(m.data, key)
	return nil
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

// MockStoreWithEval 支持Eval的mock store（用于令牌桶测试）
type MockStoreWithEval struct {
	data map[string]int64
	ttl  map[string]time.Duration
}

func (m *MockStoreWithEval) Get(key string) (int64, error) {
	return m.data[key], nil
}

func (m *MockStoreWithEval) Set(key string, value int64) error {
	m.data[key] = value
	return nil
}

func (m *MockStoreWithEval) Del(key string) error {
	delete(m.data, key)
	return nil
}

func (m *MockStoreWithEval) Incr(key string) (int64, error) {
	m.data[key]++
	return m.data[key], nil
}

func (m *MockStoreWithEval) IncrBy(key string, value int64) (int64, error) {
	m.data[key] += value
	return m.data[key], nil
}

func (m *MockStoreWithEval) Expire(key string, expiration time.Duration) error {
	m.ttl[key] = expiration
	return nil
}

func (m *MockStoreWithEval) TTL(key string) (time.Duration, error) {
	if ttl, ok := m.ttl[key]; ok {
		return ttl, nil
	}
	return -1, nil
}

func (m *MockStoreWithEval) ZAdd(key string, score float64, member string) error {
	return nil
}

func (m *MockStoreWithEval) ZRemRangeByScore(key string, min, max float64) error {
	return nil
}

func (m *MockStoreWithEval) ZCount(key string, min, max float64) (int64, error) {
	return 0, nil
}

// Eval 实现令牌桶的Lua脚本模拟
func (m *MockStoreWithEval) Eval(script string, keys []string, args ...interface{}) (interface{}, error) {
	// 模拟令牌桶Lua脚本的返回值
	// 返回格式: [allowed(0/1), remaining, capacity]
	if len(keys) > 0 && len(args) > 0 {
		key := keys[0]
		capacity := int64(10)
		if cap, ok := args[0].(int64); ok {
			capacity = cap
		}

		// 初始化令牌数
		if m.data[key] == 0 {
			m.data[key] = capacity
		}

		// 消耗一个令牌
		if m.data[key] > 0 {
			m.data[key]--
			return []interface{}{int64(1), m.data[key], capacity}, nil // 允许
		}
		return []interface{}{int64(0), m.data[key], capacity}, nil // 拒绝
	}
	return []interface{}{int64(0), int64(0), int64(0)}, nil
}

func TestFixedWindowLimiter_Allow(t *testing.T) {
	store := NewMockStore()
	limiter := NewFixedWindowLimiter(store)

	tests := []struct {
		name      string
		key       string
		limit     int64
		window    time.Duration
		requests  int
		wantAllow bool
	}{
		{
			name:      "第一次请求应该允许",
			key:       "test:1",
			limit:     5,
			window:    time.Minute,
			requests:  1,
			wantAllow: true,
		},
		{
			name:      "在限制内应该允许",
			key:       "test:2",
			limit:     5,
			window:    time.Minute,
			requests:  3,
			wantAllow: true,
		},
		{
			name:      "达到限制应该允许",
			key:       "test:3",
			limit:     5,
			window:    time.Minute,
			requests:  5,
			wantAllow: true,
		},
		{
			name:      "超过限制应该拒绝",
			key:       "test:4",
			limit:     5,
			window:    time.Minute,
			requests:  6,
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result *Context
			var err error

			// 执行多次请求
			for i := 0; i < tt.requests; i++ {
				result, err = limiter.Allow(tt.key, tt.limit, tt.window)
				if err != nil {
					t.Fatalf("Allow() error = %v", err)
				}
			}

			// 检查最后一次请求的结果
			if result.Allowed != tt.wantAllow {
				t.Errorf("Allow() Allowed = %v, want %v", result.Allowed, tt.wantAllow)
			}

			// 检查限制值
			if result.Limit != tt.limit {
				t.Errorf("Allow() Limit = %v, want %v", result.Limit, tt.limit)
			}

			// 检查剩余配额
			expectedRemaining := tt.limit - int64(tt.requests)
			if expectedRemaining < 0 {
				expectedRemaining = 0
			}
			if result.Remaining != expectedRemaining {
				t.Errorf("Allow() Remaining = %v, want %v", result.Remaining, expectedRemaining)
			}
		})
	}
}

func TestFixedWindowLimiter_Reset(t *testing.T) {
	store := NewMockStore()
	limiter := NewFixedWindowLimiter(store)

	key := "test:reset"
	limit := int64(3)
	window := time.Second

	// 用完配额
	for i := 0; i < 3; i++ {
		_, err := limiter.Allow(key, limit, window)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
	}

	// 第4次应该被拒绝
	result, err := limiter.Allow(key, limit, window)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if result.Allowed {
		t.Error("第4次请求应该被拒绝")
	}

	// 检查Reset时间戳是否合理
	if result.Reset <= time.Now().Unix() {
		t.Error("Reset时间应该在未来")
	}

	// 检查RetryAfter
	if result.RetryAfter <= 0 {
		t.Error("RetryAfter应该大于0")
	}
}
