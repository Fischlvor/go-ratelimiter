package algorithm

import (
	"testing"
	"time"
)

// MockStoreWithZSet 支持ZSet操作的模拟存储
type MockStoreWithZSet struct {
	data  map[string]int64
	zsets map[string]map[string]float64 // key -> member -> score
}

func NewMockStoreWithZSet() *MockStoreWithZSet {
	return &MockStoreWithZSet{
		data:  make(map[string]int64),
		zsets: make(map[string]map[string]float64),
	}
}

func (m *MockStoreWithZSet) Get(key string) (int64, error) {
	return m.data[key], nil
}

func (m *MockStoreWithZSet) Incr(key string) (int64, error) {
	m.data[key]++
	return m.data[key], nil
}

func (m *MockStoreWithZSet) IncrBy(key string, value int64) (int64, error) {
	m.data[key] += value
	return m.data[key], nil
}

func (m *MockStoreWithZSet) Expire(key string, expiration time.Duration) error {
	return nil
}

func (m *MockStoreWithZSet) TTL(key string) (time.Duration, error) {
	return time.Minute, nil
}

func (m *MockStoreWithZSet) ZAdd(key string, score float64, member string) error {
	if m.zsets[key] == nil {
		m.zsets[key] = make(map[string]float64)
	}
	m.zsets[key][member] = score
	return nil
}

func (m *MockStoreWithZSet) ZRemRangeByScore(key string, min, max float64) error {
	if zset, ok := m.zsets[key]; ok {
		for member, score := range zset {
			if score >= min && score <= max {
				delete(zset, member)
			}
		}
	}
	return nil
}

func (m *MockStoreWithZSet) ZCount(key string, min, max float64) (int64, error) {
	count := int64(0)
	if zset, ok := m.zsets[key]; ok {
		for _, score := range zset {
			if score >= min && score <= max {
				count++
			}
		}
	}
	return count, nil
}

func (m *MockStoreWithZSet) Eval(script string, keys []string, args ...interface{}) (interface{}, error) {
	return nil, nil
}

func TestSlidingWindowLimiter_Allow(t *testing.T) {
	store := NewMockStoreWithZSet()
	limiter := NewSlidingWindowLimiter(store)

	key := "test:sliding"
	limit := int64(5)
	window := time.Second

	tests := []struct {
		name      string
		requests  int
		wantAllow bool
	}{
		{
			name:      "第一次请求应该允许",
			requests:  1,
			wantAllow: true,
		},
		{
			name:      "在限制内应该允许",
			requests:  3,
			wantAllow: true,
		},
		{
			name:      "达到限制应该允许",
			requests:  5,
			wantAllow: true,
		},
		{
			name:      "超过限制应该拒绝",
			requests:  6,
			wantAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 重置store
			store = NewMockStoreWithZSet()
			limiter = NewSlidingWindowLimiter(store)

			var result *Context
			var err error

			// 执行多次请求
			for i := 0; i < tt.requests; i++ {
				result, err = limiter.Allow(key, limit, window)
				if err != nil {
					t.Fatalf("Allow() error = %v", err)
				}
			}

			// 检查最后一次请求的结果
			if result.Allowed != tt.wantAllow {
				t.Errorf("Allow() Allowed = %v, want %v (requests=%d)", result.Allowed, tt.wantAllow, tt.requests)
			}

			// 检查限制值
			if result.Limit != limit {
				t.Errorf("Allow() Limit = %v, want %v", result.Limit, limit)
			}
		})
	}
}

func TestSlidingWindowLimiter_WindowSliding(t *testing.T) {
	store := NewMockStoreWithZSet()
	limiter := NewSlidingWindowLimiter(store)

	key := "test:window"
	limit := int64(3)
	window := 100 * time.Millisecond

	// 快速发送3个请求
	for i := 0; i < 3; i++ {
		result, err := limiter.Allow(key, limit, window)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !result.Allowed {
			t.Errorf("请求 %d 应该被允许", i+1)
		}
	}

	// 第4个请求应该被拒绝
	result, err := limiter.Allow(key, limit, window)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if result.Allowed {
		t.Error("第4个请求应该被拒绝")
	}

	t.Logf("限流结果: Allowed=%v, Remaining=%d, Reset=%d",
		result.Allowed, result.Remaining, result.Reset)
}
