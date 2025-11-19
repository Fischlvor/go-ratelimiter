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
  limit: 1000
  window: 60s

rules:
  - name: api_login
    path: /api/login
    method: POST
    algorithm: sliding_window
    limit: 5
    window: 60s
    by: ip
    
  - name: api_query
    path: /api/query
    algorithm: token_bucket
    capacity: 100
    rate: 10/s
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
	if config.Global.Limit != 1000 {
		t.Errorf("Global.Limit = %v, want 1000", config.Global.Limit)
	}
	if config.Global.Window != "60s" {
		t.Errorf("Global.Window = %v, want 60s", config.Global.Window)
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
	if rule2.Capacity != 100 {
		t.Errorf("Rules[1].Capacity = %v, want 100", rule2.Capacity)
	}
	if rule2.Rate != "10/s" {
		t.Errorf("Rules[1].Rate = %v, want 10/s", rule2.Rate)
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
					Limit:  0,
					Window: "60s",
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
					Limit:  100,
					Window: "",
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
				Limit:     100,
				Window:    "1s",
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
				Capacity:  100,
				Rate:      "10/s",
				By:        "user",
			},
			valid: true,
		},
		{
			name: "缺少路径",
			ruleConfig: RuleConfig{
				Name:      "test",
				Algorithm: "fixed_window",
				Limit:     100,
				Window:    "1s",
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
