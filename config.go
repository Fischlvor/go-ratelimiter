package ratelimiter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 限流配置
type Config struct {
	// Default 默认配置
	Default DefaultConfig `yaml:"default"`
	// Global 全局限流配置
	Global *GlobalConfig `yaml:"global"`
	// Rules 限流规则列表
	Rules []RuleConfig `yaml:"rules"`
	// Whitelist 白名单配置
	Whitelist WhitelistConfig `yaml:"whitelist"`
}

// DefaultConfig 默认配置
type DefaultConfig struct {
	// Algorithm 默认算法
	Algorithm string `yaml:"algorithm"`
	// Enabled 是否启用限流
	Enabled bool `yaml:"enabled"`
}

// GlobalConfig 全局限流配置
type GlobalConfig struct {
	// Limit 限流阈值
	Limit int64 `yaml:"limit"`
	// Window 时间窗口（如：60s, 1m, 1h）
	Window string `yaml:"window"`
	// Algorithm 算法（可选，不指定则使用默认算法）
	Algorithm string `yaml:"algorithm"`
}

// RuleConfig 规则配置
type RuleConfig struct {
	// Name 规则名称
	Name string `yaml:"name"`
	// Path 路径匹配（支持通配符 *）
	Path string `yaml:"path"`
	// Method HTTP方法（GET/POST等，为空表示所有方法）
	Method string `yaml:"method"`
	// By 限流维度（ip/user/path/global）
	By string `yaml:"by"`
	// Algorithm 限流算法（fixed_window/sliding_window/token_bucket）
	Algorithm string `yaml:"algorithm"`
	// Limit 限流阈值（请求数）
	Limit int64 `yaml:"limit"`
	// Window 时间窗口（如：60s, 1m, 1h）
	Window string `yaml:"window"`
	// Capacity 令牌桶容量（仅token_bucket算法使用）
	Capacity int64 `yaml:"capacity"`
	// Rate 令牌生成速率（如：1/s, 10/m）
	Rate string `yaml:"rate"`
}

// WhitelistConfig 白名单配置
type WhitelistConfig struct {
	// IPs IP白名单
	IPs []string `yaml:"ips"`
	// Users 用户白名单
	Users []string `yaml:"users"`
}

// LoadConfig 从文件加载配置
func LoadConfig(filename string) (*Config, error) {
	// 读取文件
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 解析YAML
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 验证配置
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}

	return &config, nil
}

// validateConfig 验证配置
func validateConfig(config *Config) error {
	// 验证默认算法
	if config.Default.Algorithm != "" {
		if !isValidAlgorithm(config.Default.Algorithm) {
			return fmt.Errorf("无效的默认算法: %s", config.Default.Algorithm)
		}
	} else {
		// 设置默认算法
		config.Default.Algorithm = string(AlgorithmFixedWindow)
	}

	// 验证全局配置
	if config.Global != nil {
		if config.Global.Limit <= 0 {
			return fmt.Errorf("全局限流阈值必须大于0")
		}
		if _, err := parseDuration(config.Global.Window); err != nil {
			return fmt.Errorf("无效的全局时间窗口: %s", config.Global.Window)
		}
		if config.Global.Algorithm != "" && !isValidAlgorithm(config.Global.Algorithm) {
			return fmt.Errorf("无效的全局算法: %s", config.Global.Algorithm)
		}
	}

	// 验证规则
	for i, rule := range config.Rules {
		if rule.Path == "" {
			return fmt.Errorf("规则[%d]缺少path字段", i)
		}
		if rule.By == "" {
			return fmt.Errorf("规则[%d]缺少by字段", i)
		}
		if !isValidLimitBy(rule.By) {
			return fmt.Errorf("规则[%d]无效的限流维度: %s", i, rule.By)
		}

		// 验证算法
		algo := rule.Algorithm
		if algo == "" {
			algo = config.Default.Algorithm
		}
		if !isValidAlgorithm(algo) {
			return fmt.Errorf("规则[%d]无效的算法: %s", i, algo)
		}

		// 验证令牌桶特有参数
		if algo == string(AlgorithmTokenBucket) {
			if rule.Capacity <= 0 {
				return fmt.Errorf("规则[%d]令牌桶算法需要指定capacity", i)
			}
			if rule.Rate == "" {
				return fmt.Errorf("规则[%d]令牌桶算法需要指定rate", i)
			}
			if _, err := parseRate(rule.Rate); err != nil {
				return fmt.Errorf("规则[%d]无效的rate: %s", i, rule.Rate)
			}
		} else {
			// 其他算法验证limit和window
			if rule.Limit <= 0 {
				return fmt.Errorf("规则[%d]限流阈值必须大于0", i)
			}
			if _, err := parseDuration(rule.Window); err != nil {
				return fmt.Errorf("规则[%d]无效的时间窗口: %s", i, rule.Window)
			}
		}
	}

	return nil
}

// isValidAlgorithm 检查算法是否有效
func isValidAlgorithm(algo string) bool {
	switch Algorithm(algo) {
	case AlgorithmFixedWindow, AlgorithmSlidingWindow, AlgorithmTokenBucket:
		return true
	default:
		return false
	}
}

// isValidLimitBy 检查限流维度是否有效
func isValidLimitBy(by string) bool {
	switch LimitBy(by) {
	case LimitByIP, LimitByUser, LimitByPath, LimitByGlobal, LimitByCustom:
		return true
	default:
		return false
	}
}

// parseDuration 解析时间窗口字符串
func parseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// parseRate 解析速率字符串（如：1/s, 10/m, 100/h）
func parseRate(s string) (float64, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 2 {
		return 0, fmt.Errorf("无效的速率格式: %s", s)
	}

	var count float64
	if _, err := fmt.Sscanf(parts[0], "%f", &count); err != nil {
		return 0, fmt.Errorf("无效的速率数值: %s", parts[0])
	}

	var duration time.Duration
	switch parts[1] {
	case "s", "sec", "second":
		duration = time.Second
	case "m", "min", "minute":
		duration = time.Minute
	case "h", "hour":
		duration = time.Hour
	default:
		return 0, fmt.Errorf("无效的速率单位: %s", parts[1])
	}

	// 返回每秒生成的令牌数
	return count / duration.Seconds(), nil
}

// ToRule 将配置规则转换为内部规则
func (rc *RuleConfig) ToRule(defaultAlgo Algorithm) (*Rule, error) {
	rule := &Rule{
		Name:   rc.Name,
		Path:   rc.Path,
		Method: strings.ToUpper(rc.Method),
		By:     LimitBy(rc.By),
		Limit:  rc.Limit,
	}

	// 设置算法
	if rc.Algorithm != "" {
		rule.Algorithm = Algorithm(rc.Algorithm)
	} else {
		rule.Algorithm = defaultAlgo
	}

	// 根据算法设置参数
	if rule.Algorithm == AlgorithmTokenBucket {
		rule.Capacity = rc.Capacity
		rate, err := parseRate(rc.Rate)
		if err != nil {
			return nil, err
		}
		rule.Rate = rate
	} else {
		window, err := parseDuration(rc.Window)
		if err != nil {
			return nil, err
		}
		rule.Window = window
	}

	return rule, nil
}

// GetConfigPath 获取配置文件路径（支持相对路径和绝对路径）
func GetConfigPath(filename string) (string, error) {
	// 如果是绝对路径，直接返回
	if filepath.IsAbs(filename) {
		return filename, nil
	}

	// 尝试从当前工作目录查找
	if _, err := os.Stat(filename); err == nil {
		return filename, nil
	}

	// 尝试从可执行文件目录查找
	execPath, err := os.Executable()
	if err == nil {
		execDir := filepath.Dir(execPath)
		configPath := filepath.Join(execDir, filename)
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
	}

	return "", fmt.Errorf("配置文件不存在: %s", filename)
}
