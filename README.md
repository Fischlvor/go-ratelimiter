# Go RateLimiter

一个功能强大、易于使用的 Go 限流组件库，支持多种限流算法和灵活的配置方式。**框架无关**，可用于任何 Go 项目。

## ✨ 特性

- 🚀 **多种限流算法**
  - 固定窗口计数器（Fixed Window）
  - 滑动窗口计数器（Sliding Window）
  - 令牌桶算法（Token Bucket）

- 🎯 **多维度限流**
  - 全局限流
  - IP限流
  - 用户限流
  - 接口路径限流
  - 自定义维度

- ⚙️ **灵活配置**
  - 纯YAML配置文件
  - 不同规则可使用不同算法
  - 支持白名单/黑名单
  - 支持自动拉黑机制
  - 支持路径通配符

- 🔌 **框架无关**
  - 核心库不依赖任何Web框架
  - 易于集成到任何项目
  - 提供丰富的示例

- 📊 **分布式支持**
  - 基于 Redis 的分布式限流
  - 支持多实例部署
  - 原子操作保证准确性

## 📦 安装

```bash
go get github.com/Fischlvor/go-ratelimiter
```

## 🚀 快速开始

### 1. 创建配置文件

创建 `rate_limit.yaml`：

```yaml
default:
  algorithm: fixed_window
  enabled: true

global:
  limit: 1000
  window: 60s

rules:
  - name: "登录限流"
    path: /api/auth/login
    method: POST
    by: ip
    algorithm: sliding_window
    limit: 5
    window: 60s
```

### 2. 基础使用

```go
package main

import (
    "github.com/go-redis/redis"
    ratelimiter "github.com/Fischlvor/go-ratelimiter"
)

func main() {
    // 创建 Redis 客户端
    redisClient := redis.NewClient(&redis.Options{
        Addr: "localhost:6379",
    })

    // 创建限流器
    store := ratelimiter.NewRedisStore(redisClient, "ratelimit")
    limiter, err := ratelimiter.NewFromFile("rate_limit.yaml", store)
    if err != nil {
        panic(err)
    }

    // 检查请求是否允许通过
    result, err := limiter.Check(
        "/api/auth/login",  // 路径
        "POST",             // 方法
        "192.168.1.1",      // IP
        "user-uuid-123",    // 用户ID
    )
    
    if err != nil {
        // 处理错误
    }

    if !result.Allowed {
        // 请求被限流
        println("请求过于频繁，请稍后再试")
        println("剩余配额:", result.Remaining)
        println("重置时间:", result.Reset)
        return
    }

    // 处理正常请求
    println("请求通过")
}
```

## 📖 配置说明

### 默认配置

```yaml
default:
  algorithm: fixed_window  # 默认算法: fixed_window | sliding_window | token_bucket
  enabled: true            # 是否启用限流
```

### 全局限流

```yaml
global:
  limit: 1000      # 限流阈值（请求数）
  window: 60s      # 时间窗口（支持: s秒, m分钟, h小时）
  algorithm: ""    # 算法（可选，不指定则使用默认算法）
```

### 限流规则

```yaml
rules:
  - name: "规则名称"
    path: /api/path        # 路径（支持通配符 *）
    method: POST           # HTTP方法（可选，为空表示所有方法）
    by: ip                 # 限流维度: ip | user | path | global
    algorithm: fixed_window # 算法（可选，不指定则使用默认算法）
    limit: 100             # 限流阈值
    window: 60s            # 时间窗口
```

### 令牌桶算法配置

```yaml
rules:
  - name: "上传限流"
    path: /api/upload/*
    by: user
    algorithm: token_bucket
    capacity: 10    # 桶容量
    rate: 1/s       # 令牌生成速率（支持: /s, /m, /h）
```

### 白名单

```yaml
whitelist:
  ips:
    - 127.0.0.1
    - 192.168.1.100
  users:
    - user-uuid-123
```

### 黑名单

```yaml
blacklist:
  ips:
    - 192.168.1.100    # 恶意IP
    - 10.0.0.50
  users:
    - banned-user-uuid # 封禁用户
```

### 自动拉黑

```yaml
auto_ban:
  enabled: true                  # 是否启用自动拉黑
  dimensions:                    # 拉黑维度
    - ip                         # 按IP自动拉黑
    - user                       # 按用户自动拉黑
  violation_threshold: 10        # 违规次数阈值
  violation_window: 5m           # 违规统计时间窗口
  ban_duration: 1h               # 封禁时长
```

**工作原理：**
- 当请求被限流拒绝时，记录违规次数
- 在 `violation_window` 时间内累计违规次数
- 达到 `violation_threshold` 阈值后，自动加入黑名单
- 黑名单有效期为 `ban_duration`

### 检查优先级

限流器按以下优先级顺序检查请求：

```
1️⃣ 用户黑名单 → ❌ 拒绝（最高优先级）
2️⃣ 用户白名单 → ✅ 通过（不再检查IP）
3️⃣ IP黑名单   → ❌ 拒绝
4️⃣ IP白名单   → ✅ 通过
5️⃣ 限流检查   → 根据规则决定
```

**重要说明：**
- ✅ **白名单用户不受IP限制**：即使从黑名单IP访问，白名单用户也能通过
- ❌ **黑名单用户无法访问**：即使从白名单IP访问，黑名单用户也会被拒绝
- 🔄 **用户维度优先于IP维度**：用户身份认证更可靠，优先级更高

**示例场景：**

| 场景 | IP | 用户 | 结果 | 原因 |
|------|-----|------|------|------|
| 管理员出差 | 黑名单IP | 白名单用户 | ✅ 通过 | 用户白名单优先 |
| 黑客盗号 | 白名单IP | 黑名单用户 | ❌ 拒绝 | 用户黑名单优先 |
| 普通用户 | 黑名单IP | 普通用户 | ❌ 拒绝 | IP黑名单生效 |
| 未登录访问 | 黑名单IP | 未登录 | ❌ 拒绝 | IP黑名单生效 |

## 🎨 限流算法详解

### 固定窗口计数器（Fixed Window）

- **原理**：在固定时间窗口内统计请求数
- **优点**：实现简单，性能高，内存占用小
- **缺点**：存在临界问题（窗口边界可能瞬间流量翻倍）
- **适用场景**：一般API限流
- **性能**：QPS 10万+

### 滑动窗口计数器（Sliding Window）

- **原理**：使用 Redis ZSET 实现滑动时间窗口
- **优点**：解决固定窗口的临界问题，更精确
- **缺点**：实现稍复杂，内存占用稍大
- **适用场景**：需要精确控制的场景（如登录、支付）
- **性能**：QPS 5万+

### 令牌桶算法（Token Bucket）

- **原理**：使用 Lua 脚本实现，以恒定速率生成令牌
- **优点**：允许突发流量，流量平滑
- **缺点**：实现相对复杂
- **适用场景**：需要应对突发流量的场景（如上传、下载）
- **性能**：QPS 8万+

## 🔧 API 文档

### 创建限流器

```go
// 从配置文件创建
limiter, err := ratelimiter.NewFromFile("rate_limit.yaml", store)

// 从配置对象创建
config := &ratelimiter.Config{...}
limiter, err := ratelimiter.NewFromConfig(config, store)
```

### 检查限流

```go
result, err := limiter.Check(path, method, ip, userID)

// Result 结构
type Result struct {
    Allowed    bool   // 是否允许通过
    Limit      int64  // 限流阈值
    Remaining  int64  // 剩余配额
    Reset      int64  // 重置时间（Unix时间戳）
    RetryAfter int64  // 建议重试时间（秒）
}
```

### 创建 Redis 存储

```go
store := ratelimiter.NewRedisStore(redisClient, "prefix")
```

## 🔍 路径匹配

支持以下路径匹配方式：

- **精确匹配**: `/api/user/info`
- **通配符匹配**: `/api/user/*`
- **多级通配符**: `/api/*/list`

## 💡 最佳实践

### 登录接口
```yaml
- name: "登录限流"
  path: /api/auth/login
  method: POST
  by: ip
  algorithm: sliding_window  # 使用滑动窗口，精确控制
  limit: 5
  window: 60s
```

### 注册接口
```yaml
- name: "注册限流"
  path: /api/auth/register
  method: POST
  by: ip
  algorithm: sliding_window
  limit: 3
  window: 300s  # 5分钟3次，严格限制
```

### 验证码接口
```yaml
- name: "验证码限流"
  path: /api/captcha
  by: ip
  limit: 10
  window: 60s
```

### 上传接口
```yaml
- name: "上传限流"
  path: /api/upload/*
  by: user
  algorithm: token_bucket  # 使用令牌桶，允许突发
  capacity: 10
  rate: 1/s
```

### 搜索接口
```yaml
- name: "搜索限流"
  path: /api/search
  by: ip
  algorithm: sliding_window
  limit: 20
  window: 60s
```

## 🛠️ 依赖

- `github.com/go-redis/redis` - Redis客户端
- `gopkg.in/yaml.v3` - YAML解析

## 📚 示例项目

完整的使用示例请查看：[go-ratelimiter-examples](https://github.com/Fischlvor/go-ratelimiter-examples)

包含以下示例：
- **Gin框架** - 基础使用、自定义中间件、高级用法
- **Echo框架** - 集成示例
- **标准库** - http.Handler 集成

## 🌐 框架集成

### Gin 框架

```go
import ratelimiter "github.com/Fischlvor/go-ratelimiter"

func RateLimitMiddleware(limiter *ratelimiter.Limiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        result, err := limiter.Check(
            c.Request.URL.Path,
            c.Request.Method,
            c.ClientIP(),
            "", // 用户ID
        )
        
        if err != nil || !result.Allowed {
            c.JSON(429, gin.H{"message": "请求过于频繁"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

// 使用
r.Use(RateLimitMiddleware(limiter))
```

### Echo 框架

```go
func RateLimitMiddleware(limiter *ratelimiter.Limiter) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            result, err := limiter.Check(
                c.Request().URL.Path,
                c.Request().Method,
                c.RealIP(),
                "",
            )
            
            if err != nil || !result.Allowed {
                return c.JSON(429, map[string]string{"message": "请求过于频繁"})
            }
            
            return next(c)
        }
    }
}
```

### 标准库 http.Handler

```go
func RateLimitHandler(limiter *ratelimiter.Limiter, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        result, err := limiter.Check(r.URL.Path, r.Method, r.RemoteAddr, "")
        
        if err != nil || !result.Allowed {
            http.Error(w, "请求过于频繁", 429)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}
```

## 📝 配置示例

完整的配置示例请查看 [rate_limit.example.yaml](rate_limit.example.yaml)

## 📄 License

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📮 联系方式

如有问题或建议，请提交 Issue。
