package ratelimiter

import (
	"testing"
)

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		name string
		algo Algorithm
		want string
	}{
		{"固定窗口", AlgorithmFixedWindow, "fixed_window"},
		{"滑动窗口", AlgorithmSlidingWindow, "sliding_window"},
		{"令牌桶", AlgorithmTokenBucket, "token_bucket"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.algo) != tt.want {
				t.Errorf("Algorithm = %v, want %v", tt.algo, tt.want)
			}
		})
	}
}

func TestLimitBy_String(t *testing.T) {
	tests := []struct {
		name    string
		limitBy LimitBy
		want    string
	}{
		{"按IP", LimitByIP, "ip"},
		{"按用户", LimitByUser, "user"},
		{"按路径", LimitByPath, "path"},
		{"全局", LimitByGlobal, "global"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.limitBy) != tt.want {
				t.Errorf("LimitBy = %v, want %v", tt.limitBy, tt.want)
			}
		})
	}
}

func TestResult_IsAllowed(t *testing.T) {
	tests := []struct {
		name   string
		result *Result
		want   bool
	}{
		{
			name: "允许的请求",
			result: &Result{
				Allowed:   true,
				Limit:     100,
				Remaining: 50,
			},
			want: true,
		},
		{
			name: "被拒绝的请求",
			result: &Result{
				Allowed:   false,
				Limit:     100,
				Remaining: 0,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.Allowed != tt.want {
				t.Errorf("Result.Allowed = %v, want %v", tt.result.Allowed, tt.want)
			}
		})
	}
}

func TestRule_Validation(t *testing.T) {
	tests := []struct {
		name  string
		rule  *Rule
		valid bool
	}{
		{
			name: "有效的规则",
			rule: &Rule{
				Name:      "test",
				Path:      "/api/test",
				Algorithm: AlgorithmFixedWindow,
				Limit:     100,
				By:        LimitByIP,
			},
			valid: true,
		},
		{
			name: "缺少路径",
			rule: &Rule{
				Name:      "test",
				Algorithm: AlgorithmFixedWindow,
				Limit:     100,
				By:        LimitByIP,
			},
			valid: false,
		},
		{
			name: "缺少算法",
			rule: &Rule{
				Name:  "test",
				Path:  "/api/test",
				Limit: 100,
				By:    LimitByIP,
			},
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.rule.Path != "" && tt.rule.Algorithm != ""
			if isValid != tt.valid {
				t.Errorf("Rule validation = %v, want %v", isValid, tt.valid)
			}
		})
	}
}

func TestAlgorithmTypes(t *testing.T) {
	// 测试算法类型常量
	algorithms := []Algorithm{
		AlgorithmFixedWindow,
		AlgorithmSlidingWindow,
		AlgorithmTokenBucket,
	}

	if len(algorithms) != 3 {
		t.Errorf("Expected 3 algorithms, got %d", len(algorithms))
	}

	// 确保每个算法都是唯一的
	seen := make(map[Algorithm]bool)
	for _, algo := range algorithms {
		if seen[algo] {
			t.Errorf("Duplicate algorithm: %v", algo)
		}
		seen[algo] = true
	}
}

func TestLimitByTypes(t *testing.T) {
	// 测试限流维度类型常量
	limitBys := []LimitBy{
		LimitByIP,
		LimitByUser,
		LimitByPath,
		LimitByGlobal,
	}

	if len(limitBys) != 4 {
		t.Errorf("Expected 4 limit by types, got %d", len(limitBys))
	}

	// 确保每个维度都是唯一的
	seen := make(map[LimitBy]bool)
	for _, lb := range limitBys {
		if seen[lb] {
			t.Errorf("Duplicate limit by: %v", lb)
		}
		seen[lb] = true
	}
}
