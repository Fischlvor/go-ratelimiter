package algorithm

import "time"

// Context 限流上下文（独立类型，不依赖核心包）
type Context struct {
	Allowed    bool  // 是否允许请求
	Limit      int64 // 限流阈值
	Remaining  int64 // 剩余配额
	Reset      int64 // 重置时间戳
	RetryAfter int64 // 建议重试时间（秒）
}

// Store 存储接口（algorithm包需要的最小接口）
type Store interface {
	Get(key string) (int64, error)
	Incr(key string) (int64, error)
	IncrBy(key string, value int64) (int64, error)
	Expire(key string, expiration time.Duration) error
	TTL(key string) (time.Duration, error)
	ZAdd(key string, score float64, member string) error
	ZRemRangeByScore(key string, min, max float64) error
	ZCount(key string, min, max float64) (int64, error)
	Eval(script string, keys []string, args ...interface{}) (interface{}, error)
}

// Algorithm 限流算法接口
type Algorithm interface {
	Allow(key string, limit int64, window time.Duration) (*Context, error)
}
