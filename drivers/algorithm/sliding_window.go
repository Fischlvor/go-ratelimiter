package algorithm

import (
	"fmt"
	"time"
)

// SlidingWindowLimiter 滑动窗口限流器
type SlidingWindowLimiter struct {
	store Store
}

// NewSlidingWindowLimiter 创建滑动窗口限流器
func NewSlidingWindowLimiter(store Store) *SlidingWindowLimiter {
	return &SlidingWindowLimiter{
		store: store,
	}
}

// Allow 检查是否允许请求
func (l *SlidingWindowLimiter) Allow(key string, limit int64, window time.Duration) (*Context, error) {
	now := time.Now()
	windowStart := now.Add(-window)

	// 使用时间戳作为分数和成员
	score := float64(now.UnixNano())
	member := fmt.Sprintf("%d", now.UnixNano())

	// 删除窗口之外的记录
	minScore := float64(0)
	maxScore := float64(windowStart.UnixNano())
	if err := l.store.ZRemRangeByScore(key, minScore, maxScore); err != nil {
		return nil, fmt.Errorf("删除过期记录失败: %w", err)
	}

	// 统计当前窗口内的请求数
	count, err := l.store.ZCount(key, float64(windowStart.UnixNano()), float64(now.UnixNano())*2)
	if err != nil {
		return nil, fmt.Errorf("统计请求数失败: %w", err)
	}

	// 判断是否允许
	allowed := count < limit

	// 如果允许，添加当前请求
	if allowed {
		if err := l.store.ZAdd(key, score, member); err != nil {
			return nil, fmt.Errorf("添加请求记录失败: %w", err)
		}
		count++
	}

	// 设置过期时间（窗口大小的2倍，确保数据清理）
	if err := l.store.Expire(key, window*2); err != nil {
		return nil, fmt.Errorf("设置过期时间失败: %w", err)
	}

	remaining := limit - count
	if remaining < 0 {
		remaining = 0
	}

	// 计算重置时间（窗口结束时间）
	reset := now.Add(window).Unix()
	retryAfter := int64(window.Seconds())

	return &Context{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		Reset:      reset,
		RetryAfter: retryAfter,
	}, nil
}
