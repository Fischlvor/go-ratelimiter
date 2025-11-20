package ratelimiter

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Fischlvor/go-ratelimiter/drivers/algorithm"
)

// Limiter 限流器
type Limiter struct {
	config             *Config
	store              Store
	fixedWindow        *algorithm.FixedWindowLimiter
	slidingWindow      *algorithm.SlidingWindowLimiter
	tokenBucket        *algorithm.TokenBucketLimiter
	defaultAlgorithm   Algorithm
	globalRule         *Rule
	rules              []*Rule
	whitelistIPs       map[string]bool
	whitelistUsers     map[string]bool
	blacklistIPs       map[string]bool
	blacklistUsers     map[string]bool
	autoBanEnabled     bool
	autoBanDimensions  map[string]bool
	violationThreshold int64
	violationWindow    time.Duration
	banDuration        time.Duration
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
		config:            config,
		store:             store,
		fixedWindow:       algorithm.NewFixedWindowLimiter(store),
		slidingWindow:     algorithm.NewSlidingWindowLimiter(store),
		tokenBucket:       algorithm.NewTokenBucketLimiter(store),
		defaultAlgorithm:  Algorithm(config.Default.Algorithm),
		whitelistIPs:      make(map[string]bool),
		whitelistUsers:    make(map[string]bool),
		blacklistIPs:      make(map[string]bool),
		blacklistUsers:    make(map[string]bool),
		autoBanDimensions: make(map[string]bool),
	}

	// 加载白名单
	for _, ip := range config.Whitelist.IPs {
		limiter.whitelistIPs[ip] = true
	}
	for _, user := range config.Whitelist.Users {
		limiter.whitelistUsers[user] = true
	}

	// 加载黑名单
	for _, ip := range config.Blacklist.IPs {
		limiter.blacklistIPs[ip] = true
	}
	for _, user := range config.Blacklist.Users {
		limiter.blacklistUsers[user] = true
	}

	// 加载自动拉黑配置
	if config.AutoBan.Enabled {
		limiter.autoBanEnabled = true
		limiter.violationThreshold = config.AutoBan.ViolationThreshold

		// 解析违规窗口
		violationWindow, err := parseDuration(config.AutoBan.ViolationWindow)
		if err != nil {
			return nil, fmt.Errorf("解析违规窗口失败: %w", err)
		}
		limiter.violationWindow = violationWindow

		// 解析封禁时长
		banDuration, err := parseDuration(config.AutoBan.BanDuration)
		if err != nil {
			return nil, fmt.Errorf("解析封禁时长失败: %w", err)
		}
		limiter.banDuration = banDuration

		// 加载拉黑维度
		for _, dim := range config.AutoBan.Dimensions {
			limiter.autoBanDimensions[dim] = true
		}
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

	// ===== 第一优先级：用户维度 =====
	if userID != "" {
		// 1. 检查用户黑名单（最高优先级）
		if l.blacklistUsers[userID] {
			return &Result{Allowed: false}, nil
		}
		// 检查动态用户黑名单
		if l.autoBanEnabled && l.autoBanDimensions["user"] {
			banned, err := l.store.Get("blacklist:user:" + userID)
			if err != nil {
				return nil, fmt.Errorf("检查用户黑名单失败: %w", err)
			}
			if banned > 0 {
				return &Result{Allowed: false}, nil
			}
		}

		// 2. 检查用户白名单（第二优先级，直接通过，不检查IP）
		if l.whitelistUsers[userID] {
			return &Result{Allowed: true}, nil
		}
	}

	// ===== 第二优先级：IP维度 =====
	if ip != "" {
		// 3. 检查IP黑名单
		if l.blacklistIPs[ip] {
			return &Result{Allowed: false}, nil
		}
		// 检查动态IP黑名单
		if l.autoBanEnabled && l.autoBanDimensions["ip"] {
			banned, err := l.store.Get("blacklist:ip:" + ip)
			if err != nil {
				return nil, fmt.Errorf("检查IP黑名单失败: %w", err)
			}
			if banned > 0 {
				return &Result{Allowed: false}, nil
			}
		}

		// 4. 检查IP白名单
		if l.whitelistIPs[ip] {
			return &Result{Allowed: true}, nil
		}
	}

	// ===== 第三优先级：限流检查 =====
	// 5. 检查全局限流
	if l.globalRule != nil {
		result, err := l.checkRule(l.globalRule, path, method, ip, userID)
		if err != nil {
			return nil, err
		}
		if !result.Allowed {
			// 记录违规
			if err := l.recordViolation(ip, userID); err != nil {
				return nil, fmt.Errorf("记录违规失败: %w", err)
			}
			return result, nil
		}
	}

	// 6. 检查规则列表（按顺序匹配）
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

		// 如果被限流，记录违规并返回
		if !result.Allowed {
			if err := l.recordViolation(ip, userID); err != nil {
				return nil, fmt.Errorf("记录违规失败: %w", err)
			}
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

// isBlacklisted 检查是否在黑名单中（静态 + 动态）
func (l *Limiter) isBlacklisted(ip, userID string) (bool, error) {
	// 检查静态IP黑名单
	if ip != "" && l.blacklistIPs[ip] {
		return true, nil
	}

	// 检查静态用户黑名单
	if userID != "" && l.blacklistUsers[userID] {
		return true, nil
	}

	// 如果启用了自动拉黑，检查动态黑名单
	if l.autoBanEnabled {
		// 检查IP是否被自动拉黑
		if ip != "" && l.autoBanDimensions["ip"] {
			banned, err := l.store.Get("blacklist:ip:" + ip)
			if err != nil {
				return false, err
			}
			if banned > 0 {
				return true, nil
			}
		}

		// 检查用户是否被自动拉黑
		if userID != "" && l.autoBanDimensions["user"] {
			banned, err := l.store.Get("blacklist:user:" + userID)
			if err != nil {
				return false, err
			}
			if banned > 0 {
				return true, nil
			}
		}
	}

	return false, nil
}

// recordViolation 记录违规并检查是否需要自动拉黑
func (l *Limiter) recordViolation(ip, userID string) error {
	if !l.autoBanEnabled {
		return nil
	}

	// 记录IP违规
	if ip != "" && l.autoBanDimensions["ip"] {
		if err := l.checkAndBan("ip", ip); err != nil {
			return err
		}
	}

	// 记录用户违规
	if userID != "" && l.autoBanDimensions["user"] {
		if err := l.checkAndBan("user", userID); err != nil {
			return err
		}
	}

	return nil
}

// checkAndBan 检查违规次数并自动拉黑
func (l *Limiter) checkAndBan(dimension, identifier string) error {
	violationKey := fmt.Sprintf("violation:%s:%s", dimension, identifier)
	blacklistKey := fmt.Sprintf("blacklist:%s:%s", dimension, identifier)

	// 增加违规计数
	count, err := l.store.Incr(violationKey)
	if err != nil {
		return err
	}

	// 设置违规记录过期时间
	if count == 1 {
		if err := l.store.Expire(violationKey, l.violationWindow); err != nil {
			return err
		}
	}

	// 检查是否达到拉黑阈值
	if count >= l.violationThreshold {
		// 添加到黑名单
		if err := l.store.Set(blacklistKey, 1); err != nil {
			return err
		}
		if err := l.store.Expire(blacklistKey, l.banDuration); err != nil {
			return err
		}

		// 清除违规记录
		if err := l.store.Del(violationKey); err != nil {
			return err
		}
	}

	return nil
}
