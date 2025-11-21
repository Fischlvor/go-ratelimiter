package ratelimiter

import "time"

// Algorithm 限流算法类型
type Algorithm string

const (
	// AlgorithmFixedWindow 固定窗口计数器
	AlgorithmFixedWindow Algorithm = "fixed_window"
	// AlgorithmSlidingWindow 滑动窗口计数器
	AlgorithmSlidingWindow Algorithm = "sliding_window"
	// AlgorithmTokenBucket 令牌桶算法
	AlgorithmTokenBucket Algorithm = "token_bucket"
)

// LimitBy 限流维度
type LimitBy string

const (
	// LimitByIP 按IP限流
	LimitByIP LimitBy = "ip"
	// LimitByUser 按用户限流
	LimitByUser LimitBy = "user"
	// LimitByPath 按路径限流
	LimitByPath LimitBy = "path"
	// LimitByGlobal 全局限流
	LimitByGlobal LimitBy = "global"
	// LimitByCustom 自定义限流
	LimitByCustom LimitBy = "custom"
)

// Result 限流检查结果
type Result struct {
	// Allowed 是否允许通过
	Allowed bool
	// Limit 限流阈值
	Limit int64
	// Remaining 剩余配额
	Remaining int64
	// Reset 重置时间（Unix时间戳）
	Reset int64
	// RetryAfter 建议重试时间（秒）
	RetryAfter int64
}

// Rule 限流规则
type Rule struct {
	// Name 规则名称
	Name string
	// Path 路径匹配（支持通配符 *）
	Path string
	// Method HTTP方法（GET/POST等，为空表示所有方法）
	Method string
	// By 限流维度
	By LimitBy
	// Algorithm 限流算法
	Algorithm Algorithm
	// Limit 限流阈值（请求数）
	Limit int64
	// Window 时间窗口
	Window time.Duration
	// Capacity 令牌桶容量（仅token_bucket算法使用）
	Capacity int64
	// Rate 令牌生成速率（每秒生成的令牌数，仅token_bucket算法使用）
	Rate float64
	// RecordViolation 是否记录违规（用于自动拉黑）
	RecordViolation bool
	// ViolationWeight 违规权重（默认1，用于分级违规记录）
	ViolationWeight int
}

// Store 存储接口
type Store interface {
	// Get 获取键的值
	Get(key string) (int64, error)
	// Set 设置键的值
	Set(key string, value int64) error
	// Del 删除键
	Del(key string) error
	// Incr 增加键的值
	Incr(key string) (int64, error)
	// IncrBy 增加键的值指定数量
	IncrBy(key string, value int64) (int64, error)
	// Expire 设置键的过期时间
	Expire(key string, expiration time.Duration) error
	// TTL 获取键的剩余过期时间
	TTL(key string) (time.Duration, error)
	// ZAdd 添加有序集合成员
	ZAdd(key string, score float64, member string) error
	// ZRemRangeByScore 删除有序集合中指定分数范围的成员
	ZRemRangeByScore(key string, min, max float64) error
	// ZCount 统计有序集合中指定分数范围的成员数量
	ZCount(key string, min, max float64) (int64, error)
	// Eval 执行Lua脚本
	Eval(script string, keys []string, args ...interface{}) (interface{}, error)
}
