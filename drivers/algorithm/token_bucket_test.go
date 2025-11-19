package algorithm

import (
	"testing"
	"time"
)

func TestTokenBucketLimiter_Allow(t *testing.T) {
	store := &MockStoreWithEval{
		data: make(map[string]int64),
	}
	limiter := NewTokenBucketLimiter(store)

	tests := []struct {
		name      string
		key       string
		capacity  int64
		rate      float64
		requests  int
		wantAllow bool
	}{
		{
			name:      "第一次请求应该允许",
			key:       "test:1",
			capacity:  10,
			rate:      1.0,
			requests:  1,
			wantAllow: true,
		},
		{
			name:      "在容量内应该允许",
			key:       "test:2",
			capacity:  10,
			rate:      1.0,
			requests:  5,
			wantAllow: true,
		},
		{
			name:      "达到容量应该允许",
			key:       "test:3",
			capacity:  10,
			rate:      1.0,
			requests:  10,
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var result *Context
			var err error

			// 执行多次请求
			for i := 0; i < tt.requests; i++ {
				result, err = limiter.Allow(tt.key, tt.capacity, tt.rate)
				if err != nil {
					t.Fatalf("Allow() error = %v", err)
				}
			}

			// 检查最后一次请求的结果
			if result.Allowed != tt.wantAllow {
				t.Errorf("Allow() Allowed = %v, want %v", result.Allowed, tt.wantAllow)
			}

			// 检查限制值
			if result.Limit != tt.capacity {
				t.Errorf("Allow() Limit = %v, want %v", result.Limit, tt.capacity)
			}
		})
	}
}

func TestTokenBucketLimiter_RateLimit(t *testing.T) {
	// 使用支持Eval的mock store
	store := &MockStoreWithEval{
		data: make(map[string]int64),
	}
	limiter := NewTokenBucketLimiter(store)

	key := "test:rate"
	capacity := int64(5)
	rate := 1.0 // 每秒1个令牌

	// 快速消耗所有令牌
	for i := 0; i < 5; i++ {
		result, err := limiter.Allow(key, capacity, rate)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
		if !result.Allowed {
			t.Errorf("请求 %d 应该被允许", i+1)
		}
	}

	t.Log("令牌桶测试完成")
}

func TestTokenBucketLimiter_Reset(t *testing.T) {
	store := &MockStoreWithEval{
		data: make(map[string]int64),
	}
	limiter := NewTokenBucketLimiter(store)

	key := "test:reset"
	capacity := int64(3)
	rate := 1.0

	// 用完所有令牌
	for i := 0; i < 3; i++ {
		_, err := limiter.Allow(key, capacity, rate)
		if err != nil {
			t.Fatalf("Allow() error = %v", err)
		}
	}

	// 检查结果
	result, err := limiter.Allow(key, capacity, rate)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}

	// 检查Reset时间戳
	if result.Reset <= time.Now().Unix() {
		t.Error("Reset时间应该在未来")
	}

	t.Logf("Reset时间: %d, RetryAfter: %d", result.Reset, result.RetryAfter)
}

// MockStoreWithEval 支持Eval的模拟存储
type MockStoreWithEval struct {
	data map[string]int64
}

func (m *MockStoreWithEval) Get(key string) (int64, error) {
	return m.data[key], nil
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
	return nil
}

func (m *MockStoreWithEval) TTL(key string) (time.Duration, error) {
	return time.Minute, nil
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

func (m *MockStoreWithEval) Eval(script string, keys []string, args ...interface{}) (interface{}, error) {
	// 模拟令牌桶Lua脚本的返回值
	// 返回格式: [allowed(0/1), remaining, capacity]
	// capacity参数在args[0]中
	capacity := int64(10)
	if len(args) > 0 {
		if cap, ok := args[0].(int64); ok {
			capacity = cap
		}
	}
	return []interface{}{int64(1), capacity - 1, capacity}, nil
}

func BenchmarkTokenBucketLimiter_Allow(b *testing.B) {
	store := &MockStoreWithEval{
		data: make(map[string]int64),
	}
	limiter := NewTokenBucketLimiter(store)

	key := "bench:token"
	capacity := int64(1000000)
	rate := 1000.0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := limiter.Allow(key, capacity, rate)
		if err != nil {
			b.Fatal(err)
		}
	}
}
