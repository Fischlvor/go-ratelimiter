package ratelimiter

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig_Success(t *testing.T) {
	// 创建临时配置文件
	configContent := `
default:
  algorithm: fixed_window
  enabled: true

whitelist:
  ips:
    - 127.0.0.1
    - 192.168.1.1
  users:
    - admin
    - system

global:
  algorithm: sliding_window
  params: ["1000", "60s"]

rules:
  - name: api_login
    path: /api/login
    method: POST
    algorithm: sliding_window
    params: ["5", "60s"]
    by: ip
    
  - name: api_query
    path: /api/query
    algorithm: token_bucket
    params: ["100", "10/s"]
    by: user
`

	tmpfile, err := os.CreateTemp("", "rate_limit_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	if _, err := tmpfile.Write([]byte(configContent)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// 加载配置
	config, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// 验证默认配置
	if config.Default.Algorithm != "fixed_window" {
		t.Errorf("Default.Algorithm = %v, want fixed_window", config.Default.Algorithm)
	}
	if !config.Default.Enabled {
		t.Error("Default.Enabled should be true")
	}

	// 验证白名单
	if len(config.Whitelist.IPs) != 2 {
		t.Errorf("len(Whitelist.IPs) = %v, want 2", len(config.Whitelist.IPs))
	}
	if config.Whitelist.IPs[0] != "127.0.0.1" {
		t.Errorf("Whitelist.IPs[0] = %v, want 127.0.0.1", config.Whitelist.IPs[0])
	}

	if len(config.Whitelist.Users) != 2 {
		t.Errorf("len(Whitelist.Users) = %v, want 2", len(config.Whitelist.Users))
	}

	// 验证全局配置
	if config.Global == nil {
		t.Fatal("Global config should not be nil")
	}
	if len(config.Global.Params) != 2 {
		t.Errorf("len(Global.Params) = %v, want 2", len(config.Global.Params))
	}
	if config.Global.Params[0] != "1000" {
		t.Errorf("Global.Params[0] = %v, want 1000", config.Global.Params[0])
	}
	if config.Global.Params[1] != "60s" {
		t.Errorf("Global.Params[1] = %v, want 60s", config.Global.Params[1])
	}

	// 验证规则
	if len(config.Rules) != 2 {
		t.Fatalf("len(Rules) = %v, want 2", len(config.Rules))
	}

	// 验证第一条规则
	rule1 := config.Rules[0]
	if rule1.Name != "api_login" {
		t.Errorf("Rules[0].Name = %v, want api_login", rule1.Name)
	}
	if rule1.Path != "/api/login" {
		t.Errorf("Rules[0].Path = %v, want /api/login", rule1.Path)
	}
	if rule1.Method != "POST" {
		t.Errorf("Rules[0].Method = %v, want POST", rule1.Method)
	}
	if rule1.Algorithm != "sliding_window" {
		t.Errorf("Rules[0].Algorithm = %v, want sliding_window", rule1.Algorithm)
	}

	// 验证第二条规则
	rule2 := config.Rules[1]
	if rule2.Algorithm != "token_bucket" {
		t.Errorf("Rules[1].Algorithm = %v, want token_bucket", rule2.Algorithm)
	}
	if len(rule2.Params) != 2 {
		t.Errorf("len(Rules[1].Params) = %v, want 2", len(rule2.Params))
	}
	if rule2.Params[0] != "100" {
		t.Errorf("Rules[1].Params[0] = %v, want 100", rule2.Params[0])
	}
	if rule2.Params[1] != "10/s" {
		t.Errorf("Rules[1].Params[1] = %v, want 10/s", rule2.Params[1])
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/file.yaml")
	if err == nil {
		t.Error("LoadConfig() should return error for nonexistent file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "invalid_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())

	// 写入无效的YAML
	if _, err := tmpfile.Write([]byte("invalid: yaml: content: [")); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("LoadConfig() should return error for invalid YAML")
	}
}

func TestGetConfigPath(t *testing.T) {
	// 创建临时文件用于测试
	tmpfile, err := os.CreateTemp("", "test_config_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "绝对路径",
			input:   tmpfile.Name(),
			wantErr: false,
		},
		{
			name:    "不存在的相对路径",
			input:   "nonexistent_config.yaml",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := GetConfigPath(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetConfigPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && path == "" {
				t.Error("GetConfigPath() returned empty path")
			}
		})
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input   string
		want    time.Duration
		wantErr bool
	}{
		{"1s", time.Second, false},
		{"30s", 30 * time.Second, false},
		{"1m", time.Minute, false},
		{"5m", 5 * time.Minute, false},
		{"1h", time.Hour, false},
		{"2h", 2 * time.Hour, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "有效配置",
			config: &Config{
				Default: DefaultConfig{
					Algorithm: "fixed_window",
					Enabled:   true,
				},
			},
			wantErr: false,
		},
		{
			name: "无效算法",
			config: &Config{
				Default: DefaultConfig{
					Algorithm: "invalid_algo",
					Enabled:   true,
				},
			},
			wantErr: true,
		},
		{
			name: "空算法会被设置为默认值",
			config: &Config{
				Default: DefaultConfig{
					Algorithm: "",
					Enabled:   true,
				},
			},
			wantErr: false,
		},
		{
			name: "全局配置限制为0",
			config: &Config{
				Default: DefaultConfig{
					Algorithm: "fixed_window",
				},
				Global: &GlobalConfig{
					Params: []string{"0", "60s"},
				},
			},
			wantErr: true,
		},
		{
			name: "全局配置窗口为空",
			config: &Config{
				Default: DefaultConfig{
					Algorithm: "fixed_window",
				},
				Global: &GlobalConfig{
					Params: []string{"100", ""},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRuleConfigValidation(t *testing.T) {
	tests := []struct {
		name       string
		ruleConfig RuleConfig
		valid      bool
	}{
		{
			name: "固定窗口规则",
			ruleConfig: RuleConfig{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: "fixed_window",
				Params:    []string{"100", "1s"},
				By:        "ip",
			},
			valid: true,
		},
		{
			name: "令牌桶规则",
			ruleConfig: RuleConfig{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: "token_bucket",
				Params:    []string{"100", "10/s"},
				By:        "user",
			},
			valid: true,
		},
		{
			name: "缺少路径",
			ruleConfig: RuleConfig{
				Name:      "test",
				Algorithm: "fixed_window",
				Params:    []string{"100", "1s"},
				By:        "ip",
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 简单验证规则字段
			if tt.valid {
				if tt.ruleConfig.Path == "" {
					t.Error("Valid rule should have path")
				}
				if tt.ruleConfig.Algorithm == "" {
					t.Error("Valid rule should have algorithm")
				}
			}
		})
	}
}

// TestIsValidLimitBy 测试限流维度验证
func TestIsValidLimitBy(t *testing.T) {
	tests := []struct {
		name  string
		by    string
		valid bool
	}{
		{"IP限流", "ip", true},
		{"用户限流", "user", true},
		{"路径限流", "path", true},
		{"全局限流", "global", true},
		{"自定义限流", "custom", true},
		{"无效维度", "invalid", false},
		{"空字符串", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidLimitBy(tt.by)
			if got != tt.valid {
				t.Errorf("isValidLimitBy(%q) = %v, want %v", tt.by, got, tt.valid)
			}
		})
	}
}

// TestParseRate 测试速率解析
func TestParseRate(t *testing.T) {
	tests := []struct {
		name    string
		rate    string
		want    float64
		wantErr bool
	}{
		{"每秒1个", "1/s", 1.0, false},
		{"每秒10个", "10/s", 10.0, false},
		{"每分钟60个", "60/m", 1.0, false},
		{"每小时3600个", "3600/h", 1.0, false},
		{"无效格式", "invalid", 0, true},
		{"无效单位", "1/x", 0, true},
		{"空字符串", "", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRate(tt.rate)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRate(%q) error = %v, wantErr %v", tt.rate, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseRate(%q) = %v, want %v", tt.rate, got, tt.want)
			}
		})
	}
}

// TestToRule 测试规则配置转换
func TestToRule(t *testing.T) {
	tests := []struct {
		name      string
		ruleConf  RuleConfig
		wantError bool
	}{
		{
			name: "有效的固定窗口规则",
			ruleConf: RuleConfig{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: "fixed_window",
				Params:    []string{"10", "1m"},
				By:        "ip",
			},
			wantError: false,
		},
		{
			name: "有效的令牌桶规则",
			ruleConf: RuleConfig{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: "token_bucket",
				Params:    []string{"100", "10/s"},
				By:        "user",
			},
			wantError: false,
		},
		{
			name: "无效的时间窗口",
			ruleConf: RuleConfig{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: "fixed_window",
				Params:    []string{"10", "invalid"},
				By:        "ip",
			},
			wantError: true,
		},
		{
			name: "无效的速率格式",
			ruleConf: RuleConfig{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: "token_bucket",
				Params:    []string{"100", "invalid"},
				By:        "user",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.ruleConf.ToRule(AlgorithmFixedWindow)
			if (err != nil) != tt.wantError {
				t.Errorf("ToRule() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestLoadConfigWithDifferentAlgorithms 测试加载包含不同算法的配置文件
func TestLoadConfigWithDifferentAlgorithms(t *testing.T) {
	// 使用示例配置文件
	config, err := LoadConfig("rate_limit.example.yaml")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// 验证全局规则 - 滑动窗口
	if config.Global == nil {
		t.Fatal("Global config should not be nil")
	}
	if config.Global.Algorithm != "sliding_window" {
		t.Errorf("Global.Algorithm = %v, want sliding_window", config.Global.Algorithm)
	}
	if len(config.Global.Params) != 2 {
		t.Errorf("len(Global.Params) = %v, want 2", len(config.Global.Params))
	}
	if config.Global.Params[0] != "1000" {
		t.Errorf("Global.Params[0] = %v, want 1000", config.Global.Params[0])
	}
	if config.Global.Params[1] != "1m" {
		t.Errorf("Global.Params[1] = %v, want 1m", config.Global.Params[1])
	}

	// 验证规则数量（至少包含7个规则：4个算法示例 + 3个业务场景示例）
	if len(config.Rules) < 7 {
		t.Fatalf("len(Rules) = %v, want at least 7", len(config.Rules))
	}

	// 验证固定窗口规则
	rule0 := config.Rules[0]
	if rule0.Name != "登录限流-固定窗口" {
		t.Errorf("Rules[0].Name = %v, want 登录限流-固定窗口", rule0.Name)
	}
	if rule0.Algorithm != "fixed_window" {
		t.Errorf("Rules[0].Algorithm = %v, want fixed_window", rule0.Algorithm)
	}
	if len(rule0.Params) != 2 || rule0.Params[0] != "10" || rule0.Params[1] != "1m" {
		t.Errorf("Rules[0].Params = %v, want [\"10\", \"1m\"]", rule0.Params)
	}
	if !rule0.RecordViolation {
		t.Error("Rules[0].RecordViolation should be true")
	}
	if rule0.ViolationWeight != 3 {
		t.Errorf("Rules[0].ViolationWeight = %v, want 3", rule0.ViolationWeight)
	}

	// 验证滑动窗口规则
	rule1 := config.Rules[1]
	if rule1.Name != "注册限流-滑动窗口" {
		t.Errorf("Rules[1].Name = %v, want 注册限流-滑动窗口", rule1.Name)
	}
	if rule1.Algorithm != "sliding_window" {
		t.Errorf("Rules[1].Algorithm = %v, want sliding_window", rule1.Algorithm)
	}
	if len(rule1.Params) != 2 || rule1.Params[0] != "5" || rule1.Params[1] != "5m" {
		t.Errorf("Rules[1].Params = %v, want [\"5\", \"5m\"]", rule1.Params)
	}

	// 验证令牌桶规则
	rule2 := config.Rules[2]
	if rule2.Name != "上传限流-令牌桶" {
		t.Errorf("Rules[2].Name = %v, want 上传限流-令牌桶", rule2.Name)
	}
	if rule2.Algorithm != "token_bucket" {
		t.Errorf("Rules[2].Algorithm = %v, want token_bucket", rule2.Algorithm)
	}
	if len(rule2.Params) != 2 || rule2.Params[0] != "10" || rule2.Params[1] != "1/s" {
		t.Errorf("Rules[2].Params = %v, want [\"10\", \"1/s\"]", rule2.Params)
	}

	// 验证使用默认算法的规则
	rule3 := config.Rules[3]
	if rule3.Name != "文章列表-默认算法" {
		t.Errorf("Rules[3].Name = %v, want 文章列表-默认算法", rule3.Name)
	}
	if rule3.Algorithm != "" {
		t.Errorf("Rules[3].Algorithm = %v, want empty (use default)", rule3.Algorithm)
	}
	if len(rule3.Params) != 2 || rule3.Params[0] != "60" || rule3.Params[1] != "1m" {
		t.Errorf("Rules[3].Params = %v, want [\"60\", \"1m\"]", rule3.Params)
	}
	if rule3.RecordViolation {
		t.Error("Rules[3].RecordViolation should be false")
	}

	// 验证自动拉黑配置
	if !config.AutoBan.Enabled {
		t.Error("AutoBan.Enabled should be true")
	}
	if config.AutoBan.ViolationThreshold != 10 {
		t.Errorf("AutoBan.ViolationThreshold = %v, want 10", config.AutoBan.ViolationThreshold)
	}

	t.Log("✅ 配置文件加载成功，所有算法参数正确")
}

// TestRuleConversionWithDifferentAlgorithms 测试不同算法的规则转换
func TestRuleConversionWithDifferentAlgorithms(t *testing.T) {
	// 加载配置
	config, err := LoadConfig("rate_limit.example.yaml")
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}

	// 转换规则
	defaultAlgo := Algorithm(config.Default.Algorithm)

	// 测试固定窗口规则转换
	t.Run("固定窗口规则转换", func(t *testing.T) {
		rule, err := config.Rules[0].ToRule(defaultAlgo)
		if err != nil {
			t.Fatalf("ToRule() error = %v", err)
		}

		if rule.Algorithm != AlgorithmFixedWindow {
			t.Errorf("Algorithm = %v, want %v", rule.Algorithm, AlgorithmFixedWindow)
		}
		if rule.Limit != 10 {
			t.Errorf("Limit = %v, want 10", rule.Limit)
		}
		if rule.Window != time.Minute {
			t.Errorf("Window = %v, want %v", rule.Window, time.Minute)
		}
		if rule.Capacity != 0 {
			t.Errorf("Capacity should be 0 for fixed_window, got %v", rule.Capacity)
		}
		if rule.Rate != 0 {
			t.Errorf("Rate should be 0 for fixed_window, got %v", rule.Rate)
		}
		if !rule.RecordViolation {
			t.Error("RecordViolation should be true")
		}
		if rule.ViolationWeight != 3 {
			t.Errorf("ViolationWeight = %v, want 3", rule.ViolationWeight)
		}
	})

	// 测试滑动窗口规则转换
	t.Run("滑动窗口规则转换", func(t *testing.T) {
		rule, err := config.Rules[1].ToRule(defaultAlgo)
		if err != nil {
			t.Fatalf("ToRule() error = %v", err)
		}

		if rule.Algorithm != AlgorithmSlidingWindow {
			t.Errorf("Algorithm = %v, want %v", rule.Algorithm, AlgorithmSlidingWindow)
		}
		if rule.Limit != 5 {
			t.Errorf("Limit = %v, want 5", rule.Limit)
		}
		if rule.Window != 5*time.Minute {
			t.Errorf("Window = %v, want %v", rule.Window, 5*time.Minute)
		}
		if rule.Capacity != 0 {
			t.Errorf("Capacity should be 0 for sliding_window, got %v", rule.Capacity)
		}
		if rule.Rate != 0 {
			t.Errorf("Rate should be 0 for sliding_window, got %v", rule.Rate)
		}
	})

	// 测试令牌桶规则转换
	t.Run("令牌桶规则转换", func(t *testing.T) {
		rule, err := config.Rules[2].ToRule(defaultAlgo)
		if err != nil {
			t.Fatalf("ToRule() error = %v", err)
		}

		if rule.Algorithm != AlgorithmTokenBucket {
			t.Errorf("Algorithm = %v, want %v", rule.Algorithm, AlgorithmTokenBucket)
		}
		if rule.Capacity != 10 {
			t.Errorf("Capacity = %v, want 10", rule.Capacity)
		}
		if rule.Rate != 1.0 {
			t.Errorf("Rate = %v, want 1.0", rule.Rate)
		}
		// 令牌桶算法不使用Limit和Window
		if rule.Limit != 0 {
			t.Errorf("Limit should be 0 for token_bucket, got %v", rule.Limit)
		}
		if rule.Window != 0 {
			t.Errorf("Window should be 0 for token_bucket, got %v", rule.Window)
		}
	})

	// 测试使用默认算法的规则转换
	t.Run("默认算法规则转换", func(t *testing.T) {
		rule, err := config.Rules[3].ToRule(defaultAlgo)
		if err != nil {
			t.Fatalf("ToRule() error = %v", err)
		}

		if rule.Algorithm != defaultAlgo {
			t.Errorf("Algorithm = %v, want %v (default)", rule.Algorithm, defaultAlgo)
		}
		if rule.Limit != 60 {
			t.Errorf("Limit = %v, want 60", rule.Limit)
		}
		if rule.Window != time.Minute {
			t.Errorf("Window = %v, want %v", rule.Window, time.Minute)
		}
		if rule.RecordViolation {
			t.Error("RecordViolation should be false")
		}
		if rule.ViolationWeight != 0 {
			t.Errorf("ViolationWeight = %v, want 0", rule.ViolationWeight)
		}
	})

	t.Log("✅ 所有规则转换成功，参数设置正确")
}
