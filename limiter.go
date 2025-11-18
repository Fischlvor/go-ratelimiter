package ratelimiter

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Fischlvor/go-ratelimiter/drivers/algorithm"
)

// Limiter 限流器
type Limiter struct {
	config           *Config
	store            Store
	fixedWindow      *algorithm.FixedWindowLimiter
	slidingWindow    *algorithm.SlidingWindowLimiter
	tokenBucket      *algorithm.TokenBucketLimiter
	defaultAlgorithm Algorithm
	globalRule       *Rule
	rules            []*Rule
	whitelistIPs     map[string]bool
	whitelistUsers   map[string]bool
}

// NewFromFile 从配置文件创建限流器
func NewFromFile(configFile string, store Store) (*Limiter, error) {
	// 获取配置文件路径
	configPath, err := GetConfigPath(configFile)
	if err != nil {
		return nil, err
	}

	// 加载配置
	config, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}

	return NewFromConfig(config, store)
}

// NewFromConfig 从配置对象创建限流器
func NewFromConfig(config *Config, store Store) (*Limiter, error) {
	limiter := &Limiter{
		config:           config,
		store:            store,
		fixedWindow:      algorithm.NewFixedWindowLimiter(store),
		slidingWindow:    algorithm.NewSlidingWindowLimiter(store),
		tokenBucket:      algorithm.NewTokenBucketLimiter(store),
		defaultAlgorithm: Algorithm(config.Default.Algorithm),
		whitelistIPs:     make(map[string]bool),
		whitelistUsers:   make(map[string]bool),
	}

	// 加载白名单
	for _, ip := range config.Whitelist.IPs {
		limiter.whitelistIPs[ip] = true
	}
	for _, user := range config.Whitelist.Users {
		limiter.whitelistUsers[user] = true
	}

	// 转换全局规则
	if config.Global != nil {
		algo := Algorithm(config.Global.Algorithm)
		if algo == "" {
			algo = limiter.defaultAlgorithm
		}

		window, err := parseDuration(config.Global.Window)
		if err != nil {
			return nil, fmt.Errorf("解析全局窗口失败: %w", err)
		}

		limiter.globalRule = &Rule{
			Name:      "全局限流",
			Path:      "*",
			By:        LimitByGlobal,
			Algorithm: algo,
			Limit:     config.Global.Limit,
			Window:    window,
		}
	}

	// 转换规则列表
	for _, ruleConfig := range config.Rules {
		rule, err := ruleConfig.ToRule(limiter.defaultAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("转换规则失败: %w", err)
		}
		limiter.rules = append(limiter.rules, rule)
	}

	return limiter, nil
}

// Check 检查请求是否允许通过
func (l *Limiter) Check(path, method, ip, userID string) (*Result, error) {
	// 检查是否启用限流
	if !l.config.Default.Enabled {
		return &Result{Allowed: true}, nil
	}

	// 检查IP白名单
	if l.whitelistIPs[ip] {
		return &Result{Allowed: true}, nil
	}

	// 检查用户白名单
	if userID != "" && l.whitelistUsers[userID] {
		return &Result{Allowed: true}, nil
	}

	// 1. 检查全局限流
	if l.globalRule != nil {
		result, err := l.checkRule(l.globalRule, path, method, ip, userID)
		if err != nil {
			return nil, err
		}
		if !result.Allowed {
			return result, nil
		}
	}

	// 2. 检查规则列表（按顺序匹配）
	for _, rule := range l.rules {
		// 检查路径是否匹配
		if !l.matchPath(rule.Path, path) {
			continue
		}

		// 检查方法是否匹配
		if rule.Method != "" && rule.Method != method {
			continue
		}

		// 匹配到规则，执行限流检查
		result, err := l.checkRule(rule, path, method, ip, userID)
		if err != nil {
			return nil, err
		}

		// 如果被限流，直接返回
		if !result.Allowed {
			return result, nil
		}
	}

	// 所有检查都通过
	return &Result{Allowed: true}, nil
}

// checkRule 检查单个规则
func (l *Limiter) checkRule(rule *Rule, path, method, ip, userID string) (*Result, error) {
	// 构建限流key
	key := l.buildKey(rule, path, ip, userID)

	// 根据算法执行限流检查
	var ctx *algorithm.Context
	var err error

	switch rule.Algorithm {
	case AlgorithmFixedWindow:
		ctx, err = l.fixedWindow.Allow(key, rule.Limit, rule.Window)
	case AlgorithmSlidingWindow:
		ctx, err = l.slidingWindow.Allow(key, rule.Limit, rule.Window)
	case AlgorithmTokenBucket:
		ctx, err = l.tokenBucket.Allow(key, rule.Capacity, rule.Rate)
	default:
		return nil, fmt.Errorf("未知的算法: %s", rule.Algorithm)
	}

	if err != nil {
		return nil, err
	}

	// 转换algorithm.Context到ratelimiter.Result
	return &Result{
		Allowed:    ctx.Allowed,
		Limit:      ctx.Limit,
		Remaining:  ctx.Remaining,
		Reset:      ctx.Reset,
		RetryAfter: ctx.RetryAfter,
	}, nil
}

// buildKey 构建限流key
func (l *Limiter) buildKey(rule *Rule, path, ip, userID string) string {
	var parts []string

	// 添加规则名称或路径
	if rule.Name != "" {
		parts = append(parts, rule.Name)
	} else {
		parts = append(parts, path)
	}

	// 根据限流维度添加key部分
	switch rule.By {
	case LimitByIP:
		parts = append(parts, "ip", ip)
	case LimitByUser:
		if userID != "" {
			parts = append(parts, "user", userID)
		} else {
			// 如果没有用户ID，降级为IP限流
			parts = append(parts, "ip", ip)
		}
	case LimitByPath:
		parts = append(parts, "path", path)
	case LimitByGlobal:
		parts = append(parts, "global")
	}

	return strings.Join(parts, ":")
}

// matchPath 检查路径是否匹配
func (l *Limiter) matchPath(pattern, path string) bool {
	// 精确匹配
	if pattern == path {
		return true
	}

	// 通配符匹配
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false
	}

	return matched
}

// IsEnabled 检查限流是否启用
func (l *Limiter) IsEnabled() bool {
	return l.config.Default.Enabled
}

// GetConfig 获取配置
func (l *Limiter) GetConfig() *Config {
	return l.config
}
