package algorithm

import (
	"fmt"
	"time"
)

// FixedWindowLimiter 固定窗口限流器
type FixedWindowLimiter struct {
	store Store
}

// NewFixedWindowLimiter 创建固定窗口限流器
func NewFixedWindowLimiter(store Store) *FixedWindowLimiter {
	return &FixedWindowLimiter{
		store: store,
	}
}

// Allow 检查是否允许请求
func (l *FixedWindowLimiter) Allow(key string, limit int64, window time.Duration) (*Context, error) {
	// 递增计数
	count, err := l.store.Incr(key)
	if err != nil {
		return nil, fmt.Errorf("递增计数失败: %w", err)
	}

	// 如果是第一次请求，设置过期时间
	if count == 1 {
		if err := l.store.Expire(key, window); err != nil {
			return nil, fmt.Errorf("设置过期时间失败: %w", err)
		}
	}

	// 获取剩余时间
	ttl, err := l.store.TTL(key)
	if err != nil {
		return nil, fmt.Errorf("获取TTL失败: %w", err)
	}

	// 计算重置时间
	reset := time.Now().Add(ttl).Unix()

	// 判断是否超过限制
	allowed := count <= limit
	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	return &Context{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		Reset:      reset,
		RetryAfter: int64(ttl.Seconds()),
	}, nil
}
