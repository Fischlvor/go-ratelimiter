package algorithm

import (
	"fmt"
	"time"
)

// TokenBucketLimiter 令牌桶限流器
type TokenBucketLimiter struct {
	store Store
}

// NewTokenBucketLimiter 创建令牌桶限流器
func NewTokenBucketLimiter(store Store) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		store: store,
	}
}

// Allow 检查是否允许请求
func (l *TokenBucketLimiter) Allow(key string, capacity int64, rate float64) (*Context, error) {
	now := time.Now().Unix()

	// Lua脚本实现令牌桶算法
	script := `
		local key = KEYS[1]
		local capacity = tonumber(ARGV[1])
		local rate = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		local requested = tonumber(ARGV[4])

		-- 获取上次更新时间和当前令牌数
		local last_time = tonumber(redis.call('HGET', key, 'last_time') or now)
		local tokens = tonumber(redis.call('HGET', key, 'tokens') or capacity)

		-- 计算新增的令牌数
		local delta = math.max(0, now - last_time)
		local new_tokens = math.min(capacity, tokens + delta * rate)

		-- 判断是否有足够的令牌
		local allowed = new_tokens >= requested
		local remaining = new_tokens

		if allowed then
			remaining = new_tokens - requested
			-- 更新令牌数和时间
			redis.call('HSET', key, 'tokens', remaining)
			redis.call('HSET', key, 'last_time', now)
			-- 设置过期时间
			redis.call('EXPIRE', key, math.ceil(capacity / rate) + 60)
		else
			-- 即使不允许，也更新令牌数（但不消耗）
			redis.call('HSET', key, 'tokens', new_tokens)
			redis.call('HSET', key, 'last_time', now)
			redis.call('EXPIRE', key, math.ceil(capacity / rate) + 60)
		end

		return {allowed and 1 or 0, remaining, capacity}
	`

	// 执行Lua脚本
	result, err := l.store.Eval(script, []string{key}, capacity, rate, now, 1)
	if err != nil {
		return nil, fmt.Errorf("执行Lua脚本失败: %w", err)
	}

	// 解析结果
	values, ok := result.([]interface{})
	if !ok || len(values) != 3 {
		return nil, fmt.Errorf("Lua脚本返回格式错误")
	}

	allowed := values[0].(int64) == 1
	remaining := values[1].(int64)
	limit := values[2].(int64)

	// 计算重试时间
	var retryAfter int64
	if !allowed {
		// 需要等待的时间 = (需要的令牌数 - 当前令牌数) / 速率
		tokensNeeded := 1 - remaining
		if tokensNeeded > 0 {
			retryAfter = int64(float64(tokensNeeded) / rate)
			if retryAfter < 1 {
				retryAfter = 1
			}
		}
	}

	return &Context{
		Allowed:    allowed,
		Limit:      limit,
		Remaining:  remaining,
		Reset:      now + int64(float64(capacity)/rate),
		RetryAfter: retryAfter,
	}, nil
}
