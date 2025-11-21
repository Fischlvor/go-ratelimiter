package ratelimiter

import (
	"os"
	"strings"
	"testing"
	"time"
)

// MockStore 用于测试的模拟存储
type MockStore struct {
	data map[string]int64
	ttl  map[string]time.Duration
}

func NewMockStore() *MockStore {
	return &MockStore{
		data: make(map[string]int64),
		ttl:  make(map[string]time.Duration),
	}
}

func (m *MockStore) Get(key string) (int64, error) {
	return m.data[key], nil
}

func (m *MockStore) Set(key string, value int64) error {
	m.data[key] = value
	return nil
}

func (m *MockStore) Del(key string) error {
	delete(m.data, key)
	return nil
}

func (m *MockStore) Incr(key string) (int64, error) {
	m.data[key]++
	return m.data[key], nil
}

func (m *MockStore) IncrBy(key string, value int64) (int64, error) {
	m.data[key] += value
	return m.data[key], nil
}

func (m *MockStore) Expire(key string, expiration time.Duration) error {
	m.ttl[key] = expiration
	return nil
}

func (m *MockStore) TTL(key string) (time.Duration, error) {
	if ttl, ok := m.ttl[key]; ok {
		return ttl, nil
	}
	return -1, nil
}

func (m *MockStore) ZAdd(key string, score float64, member string) error {
	return nil
}

func (m *MockStore) ZRemRangeByScore(key string, min, max float64) error {
	return nil
}

func (m *MockStore) ZCount(key string, min, max float64) (int64, error) {
	return 0, nil
}

func (m *MockStore) Eval(script string, keys []string, args ...interface{}) (interface{}, error) {
	return nil, nil
}

func TestNewFromConfig(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Whitelist: WhitelistConfig{
			IPs:   []string{"127.0.0.1"},
			Users: []string{"admin"},
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	if limiter == nil {
		t.Fatal("limiter should not be nil")
	}

	// 检查白名单
	if !limiter.whitelistIPs["127.0.0.1"] {
		t.Error("127.0.0.1 should be in whitelist")
	}
	if !limiter.whitelistUsers["admin"] {
		t.Error("admin should be in whitelist")
	}
}

// TestNewFromFile 测试从文件创建限流器
func TestNewFromFile(t *testing.T) {
	// 创建临时配置文件
	tmpFile, err := os.CreateTemp("", "rate_limit_*.yaml")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// 写入配置
	configContent := `default:
  algorithm: fixed_window
  enabled: true

rules:
  - name: test_rule
    path: /api/test
    params: ["10", "1m"]
    by: ip
`
	if _, err := tmpFile.WriteString(configContent); err != nil {
		t.Fatalf("写入配置失败: %v", err)
	}
	tmpFile.Close()

	// 测试成功加载
	store := NewMockStore()
	limiter, err := NewFromFile(tmpFile.Name(), store)
	if err != nil {
		t.Fatalf("从文件创建限流器失败: %v", err)
	}
	if limiter == nil {
		t.Error("限流器不应该为空")
	}
	if len(limiter.rules) != 1 {
		t.Errorf("期望1个规则，实际 %d", len(limiter.rules))
	}

	// 测试文件不存在
	_, err = NewFromFile("nonexistent.yaml", store)
	if err == nil {
		t.Error("期望文件不存在错误")
	}
}

// TestNewFromFile_InvalidConfig 测试无效配置文件
func TestNewFromFile_InvalidConfig(t *testing.T) {
	// 创建无效配置文件
	tmpFile, err := os.CreateTemp("", "invalid_*.yaml")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// 写入无效配置
	tmpFile.WriteString("invalid: yaml: content:")
	tmpFile.Close()

	store := NewMockStore()
	_, err = NewFromFile(tmpFile.Name(), store)
	if err == nil {
		t.Error("期望解析错误")
	}
}

func TestLimiter_Check_Whitelist(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
		Whitelist: WhitelistConfig{
			IPs:   []string{"192.168.1.1"},
			Users: []string{"vip_user"},
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	// 测试IP白名单
	result, err := limiter.Check("/api/test", "GET", "192.168.1.1", "")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Allowed {
		t.Error("白名单IP应该被允许")
	}

	// 测试用户白名单
	result, err = limiter.Check("/api/test", "GET", "1.2.3.4", "vip_user")
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !result.Allowed {
		t.Error("白名单用户应该被允许")
	}
}

func TestLimiter_BuildKey(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	tests := []struct {
		name    string
		rule    *Rule
		path    string
		ip      string
		userID  string
		wantKey string
	}{
		{
			name: "按IP限流",
			rule: &Rule{
				Name: "test_rule",
				By:   LimitByIP,
			},
			path:    "/api/test",
			ip:      "1.2.3.4",
			userID:  "",
			wantKey: "test_rule:ip:1.2.3.4",
		},
		{
			name: "按用户限流",
			rule: &Rule{
				Name: "test_rule",
				By:   LimitByUser,
			},
			path:    "/api/test",
			ip:      "1.2.3.4",
			userID:  "user123",
			wantKey: "test_rule:user:user123",
		},
		{
			name: "全局限流",
			rule: &Rule{
				Name: "test_rule",
				By:   LimitByGlobal,
			},
			path:    "/api/test",
			ip:      "1.2.3.4",
			userID:  "user123",
			wantKey: "test_rule:global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := limiter.buildKey(tt.rule, tt.path, tt.ip, tt.userID)
			if key != tt.wantKey {
				t.Errorf("buildKey() = %v, want %v", key, tt.wantKey)
			}
		})
	}
}

func TestLimiter_CheckRule(t *testing.T) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("NewFromConfig() error = %v", err)
	}

	rule := &Rule{
		Name:      "test",
		Algorithm: AlgorithmFixedWindow,
		Limit:     5,
		Window:    time.Minute,
		By:        LimitByIP,
	}

	// 发送5个请求，都应该被允许
	for i := 0; i < 5; i++ {
		result, err := limiter.checkRule(rule, "/api/test", "GET", "1.2.3.4", "")
		if err != nil {
			t.Fatalf("checkRule() error = %v", err)
		}
		if !result.Allowed {
			t.Errorf("请求 %d 应该被允许", i+1)
		}
	}

	// 第6个请求应该被拒绝
	result, err := limiter.checkRule(rule, "/api/test", "GET", "1.2.3.4", "")
	if err != nil {
		t.Fatalf("checkRule() error = %v", err)
	}
	if result.Allowed {
		t.Error("第6个请求应该被拒绝")
	}
	if result.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0", result.Remaining)
	}
}

func BenchmarkLimiter_Check(b *testing.B) {
	store := NewMockStore()

	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
		},
		Global: &GlobalConfig{
			Algorithm: "fixed_window",
			Params:    []string{"1000000", "1s"},
		},
	}

	limiter, err := NewFromConfig(config, store)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := limiter.Check("/api/test", "GET", "1.2.3.4", "")
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestStaticIPBlacklist 测试静态IP黑名单
func TestStaticIPBlacklist(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Blacklist: BlacklistConfig{
			IPs: []string{"192.168.1.100"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 黑名单IP应该被拒绝
	result, err := limiter.Check("/api/test", "GET", "192.168.1.100", "")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Allowed {
		t.Error("黑名单IP应该被拒绝")
	}

	// 正常IP应该通过
	result, err = limiter.Check("/api/test", "GET", "1.2.3.4", "")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if !result.Allowed {
		t.Error("正常IP应该通过")
	}
}

// TestStaticUserBlacklist 测试静态用户黑名单
func TestStaticUserBlacklist(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Blacklist: BlacklistConfig{
			Users: []string{"banned-user-123"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 黑名单用户应该被拒绝
	result, err := limiter.Check("/api/test", "GET", "1.2.3.4", "banned-user-123")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Allowed {
		t.Error("黑名单用户应该被拒绝")
	}

	// 正常用户应该通过
	result, err = limiter.Check("/api/test", "GET", "1.2.3.4", "normal-user")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if !result.Allowed {
		t.Error("正常用户应该通过")
	}
}

// TestBlacklistPriority 测试黑名单优先级高于白名单
func TestBlacklistPriority(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Whitelist: WhitelistConfig{
			IPs: []string{"192.168.1.100"},
		},
		Blacklist: BlacklistConfig{
			IPs: []string{"192.168.1.100"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 同时在黑名单和白名单的IP，黑名单优先
	result, err := limiter.Check("/api/test", "GET", "192.168.1.100", "")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Allowed {
		t.Error("黑名单应该优先于白名单")
	}
}

// TestWhitelistUserWithBlacklistIP 测试白名单用户从黑名单IP访问
func TestWhitelistUserWithBlacklistIP(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Whitelist: WhitelistConfig{
			Users: []string{"admin-uuid"},
		},
		Blacklist: BlacklistConfig{
			IPs: []string{"192.168.1.100"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 白名单用户从黑名单IP访问，应该通过（用户白名单优先）
	result, err := limiter.Check("/api/test", "GET", "192.168.1.100", "admin-uuid")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if !result.Allowed {
		t.Error("白名单用户应该不受IP黑名单限制")
	}
}

// TestBlacklistUserWithWhitelistIP 测试黑名单用户从白名单IP访问
func TestBlacklistUserWithWhitelistIP(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Whitelist: WhitelistConfig{
			IPs: []string{"127.0.0.1"},
		},
		Blacklist: BlacklistConfig{
			Users: []string{"hacker-uuid"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 黑名单用户从白名单IP访问，应该被拒绝（用户黑名单优先）
	result, err := limiter.Check("/api/test", "GET", "127.0.0.1", "hacker-uuid")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Allowed {
		t.Error("黑名单用户应该被拒绝，即使IP在白名单")
	}
}

// TestNormalUserWithBlacklistIP 测试普通用户从黑名单IP访问
func TestNormalUserWithBlacklistIP(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Blacklist: BlacklistConfig{
			IPs: []string{"192.168.1.100"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 普通用户从黑名单IP访问，应该被拒绝
	result, err := limiter.Check("/api/test", "GET", "192.168.1.100", "normal-user")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if result.Allowed {
		t.Error("黑名单IP应该被拒绝")
	}
}

// TestPriorityOrder 测试完整的优先级顺序
func TestPriorityOrder(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Whitelist: WhitelistConfig{
			IPs:   []string{"10.0.0.1"},
			Users: []string{"vip-user"},
		},
		Blacklist: BlacklistConfig{
			IPs:   []string{"192.168.1.100"},
			Users: []string{"banned-user"},
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	tests := []struct {
		name     string
		ip       string
		userID   string
		expected bool
		reason   string
	}{
		{
			name:     "黑名单用户+白名单IP",
			ip:       "10.0.0.1",
			userID:   "banned-user",
			expected: false,
			reason:   "用户黑名单优先级最高",
		},
		{
			name:     "白名单用户+黑名单IP",
			ip:       "192.168.1.100",
			userID:   "vip-user",
			expected: true,
			reason:   "用户白名单优先于IP黑名单",
		},
		{
			name:     "普通用户+黑名单IP",
			ip:       "192.168.1.100",
			userID:   "normal-user",
			expected: false,
			reason:   "IP黑名单生效",
		},
		{
			name:     "普通用户+白名单IP",
			ip:       "10.0.0.1",
			userID:   "normal-user",
			expected: true,
			reason:   "IP白名单生效",
		},
		{
			name:     "白名单用户+普通IP",
			ip:       "1.2.3.4",
			userID:   "vip-user",
			expected: true,
			reason:   "用户白名单生效",
		},
		{
			name:     "黑名单用户+普通IP",
			ip:       "1.2.3.4",
			userID:   "banned-user",
			expected: false,
			reason:   "用户黑名单生效",
		},
		{
			name:     "未登录+黑名单IP",
			ip:       "192.168.1.100",
			userID:   "",
			expected: false,
			reason:   "IP黑名单生效",
		},
		{
			name:     "未登录+白名单IP",
			ip:       "10.0.0.1",
			userID:   "",
			expected: true,
			reason:   "IP白名单生效",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := limiter.Check("/api/test", "GET", tt.ip, tt.userID)
			if err != nil {
				t.Fatalf("检查失败: %v", err)
			}
			if result.Allowed != tt.expected {
				t.Errorf("期望 %v，实际 %v，原因：%s", tt.expected, result.Allowed, tt.reason)
			}
		})
	}
}

// TestAutoBanIP 测试IP自动拉黑
func TestAutoBanIP(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Rules: []RuleConfig{
			{
				Name:            "test-rule",
				Path:            "/api/test",
				By:              "ip",
				Algorithm:       "fixed_window",
				Params:          []string{"1", "1m"},
				RecordViolation: true, // 记录违规
				ViolationWeight: 1,    // 每次违规1分
			},
		},
		AutoBan: AutoBanConfig{
			Enabled:            true,
			Dimensions:         []string{"ip"},
			ViolationThreshold: 3,
			ViolationWindow:    "5m",
			BanDuration:        "1h",
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	ip := "1.2.3.4"

	// 第1次违规
	limiter.Check("/api/test", "GET", ip, "")
	limiter.Check("/api/test", "GET", ip, "") // 触发限流

	// 第2次违规
	limiter.Check("/api/test", "GET", ip, "")

	// 第3次违规，应该被自动拉黑
	limiter.Check("/api/test", "GET", ip, "")

	// 检查是否被拉黑
	banned, err := limiter.isBlacklisted(ip, "")
	if err != nil {
		t.Fatalf("检查黑名单失败: %v", err)
	}
	if !banned {
		t.Error("达到违规阈值后应该被自动拉黑")
	}
}

// TestAutoBanUser 测试用户自动拉黑
func TestAutoBanUser(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Rules: []RuleConfig{
			{
				Name:            "test-rule",
				Path:            "/api/test",
				By:              "user",
				Algorithm:       "fixed_window",
				Params:          []string{"1", "1m"},
				RecordViolation: true, // 记录违规
				ViolationWeight: 1,    // 每次违规1分
			},
		},
		AutoBan: AutoBanConfig{
			Enabled:            true,
			Dimensions:         []string{"user"},
			ViolationThreshold: 2,
			ViolationWindow:    "5m",
			BanDuration:        "1h",
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	userID := "test-user-123"

	// 第1次违规
	limiter.Check("/api/test", "GET", "1.2.3.4", userID)
	limiter.Check("/api/test", "GET", "1.2.3.4", userID) // 触发限流

	// 第2次违规，应该被自动拉黑
	limiter.Check("/api/test", "GET", "1.2.3.4", userID)

	// 检查是否被拉黑
	banned, err := limiter.isBlacklisted("", userID)
	if err != nil {
		t.Fatalf("检查黑名单失败: %v", err)
	}
	if !banned {
		t.Error("达到违规阈值后应该被自动拉黑")
	}
}

// TestAutoBanMultipleDimensions 测试多维度自动拉黑
func TestAutoBanMultipleDimensions(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
		Rules: []RuleConfig{
			{
				Name:            "test-rule",
				Path:            "/api/test",
				By:              "user",
				Algorithm:       "fixed_window",
				Params:          []string{"1", "1m"},
				RecordViolation: true, // 记录违规
				ViolationWeight: 1,    // 每次违规1分
			},
		},
		AutoBan: AutoBanConfig{
			Enabled:            true,
			Dimensions:         []string{"ip", "user"},
			ViolationThreshold: 2,
			ViolationWindow:    "5m",
			BanDuration:        "1h",
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	ip := "1.2.3.4"
	userID := "test-user"

	// 触发2次违规
	limiter.Check("/api/test", "GET", ip, userID)
	limiter.Check("/api/test", "GET", ip, userID) // 第1次违规
	limiter.Check("/api/test", "GET", ip, userID) // 第2次违规

	// IP和用户都应该被拉黑
	bannedIP, _ := limiter.isBlacklisted(ip, "")
	bannedUser, _ := limiter.isBlacklisted("", userID)

	if !bannedIP {
		t.Error("IP应该被自动拉黑")
	}
	if !bannedUser {
		t.Error("用户应该被自动拉黑")
	}
}

// TestMatchPath 测试路径匹配
func TestMatchPath(t *testing.T) {
	limiter := &Limiter{}

	tests := []struct {
		name    string
		pattern string
		path    string
		want    bool
	}{
		{"精确匹配", "/api/test", "/api/test", true},
		{"不匹配", "/api/test", "/api/user", false},
		{"通配符匹配", "/api/*", "/api/test", true},
		{"通配符不匹配", "/api/*", "/api/test/123", false},
		{"多级通配符", "/api/*/user", "/api/v1/user", true},
		{"无效模式", "[invalid", "/api/test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := limiter.matchPath(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}

// TestIsEnabled 测试IsEnabled方法
func TestIsEnabled(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		want    bool
	}{
		{"启用限流", true, true},
		{"禁用限流", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := &Limiter{
				config: &Config{
					Default: DefaultConfig{
						Enabled: tt.enabled,
					},
				},
			}
			if got := limiter.IsEnabled(); got != tt.want {
				t.Errorf("IsEnabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGetConfig 测试GetConfig方法
func TestGetConfig(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
	}

	limiter := &Limiter{
		config: config,
	}

	got := limiter.GetConfig()
	if got != config {
		t.Error("GetConfig() 返回的配置不正确")
	}
	if got.Default.Algorithm != "fixed_window" {
		t.Errorf("期望算法 fixed_window，实际 %s", got.Default.Algorithm)
	}
}

// TestCheck_Disabled 测试禁用限流时的行为
func TestCheck_Disabled(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   false, // 禁用
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 禁用时应该直接通过
	result, err := limiter.Check("/api/test", "GET", "1.2.3.4", "user123")
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if !result.Allowed {
		t.Error("禁用限流时应该允许所有请求")
	}
}

// TestCheckRule_UnknownAlgorithm 测试未知算法
func TestCheckRule_UnknownAlgorithm(t *testing.T) {
	config := &Config{
		Default: DefaultConfig{
			Algorithm: "fixed_window",
			Enabled:   true,
		},
	}

	store := NewMockStore()
	limiter, err := NewFromConfig(config, store)
	if err != nil {
		t.Fatalf("创建限流器失败: %v", err)
	}

	// 创建一个未知算法的规则
	rule := &Rule{
		Name:      "test",
		Path:      "/api/test",
		Algorithm: "unknown_algorithm",
		Limit:     10,
		Window:    time.Minute,
	}

	_, err = limiter.checkRule(rule, "/api/test", "GET", "1.2.3.4", "")
	if err == nil {
		t.Error("期望未知算法错误")
	}
	if err != nil && !strings.Contains(err.Error(), "未知的算法") {
		t.Errorf("期望'未知的算法'错误，实际: %v", err)
	}
}

// TestBuildKey 测试buildKey方法
func TestBuildKey(t *testing.T) {
	limiter := &Limiter{}

	tests := []struct {
		name   string
		rule   *Rule
		path   string
		ip     string
		userID string
		want   string
	}{
		{
			name:   "按IP限流",
			rule:   &Rule{Name: "test", By: LimitByIP},
			path:   "/api/test",
			ip:     "1.2.3.4",
			userID: "",
			want:   "test:ip:1.2.3.4",
		},
		{
			name:   "按用户限流",
			rule:   &Rule{Name: "test", By: LimitByUser},
			path:   "/api/test",
			ip:     "1.2.3.4",
			userID: "user123",
			want:   "test:user:user123",
		},
		{
			name:   "按用户限流但无用户ID",
			rule:   &Rule{Name: "test", By: LimitByUser},
			path:   "/api/test",
			ip:     "1.2.3.4",
			userID: "",
			want:   "test:ip:1.2.3.4", // 降级为IP
		},
		{
			name:   "按路径限流",
			rule:   &Rule{Name: "test", By: LimitByPath},
			path:   "/api/test",
			ip:     "1.2.3.4",
			userID: "",
			want:   "test:path:/api/test",
		},
		{
			name:   "全局限流",
			rule:   &Rule{Name: "test", By: LimitByGlobal},
			path:   "/api/test",
			ip:     "1.2.3.4",
			userID: "",
			want:   "test:global",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := limiter.buildKey(tt.rule, tt.path, tt.ip, tt.userID)
			if got != tt.want {
				t.Errorf("buildKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
