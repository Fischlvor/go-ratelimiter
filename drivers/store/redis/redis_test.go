package redis

import (
	"testing"
	"time"

	"github.com/go-redis/redis"
)

// 注意：这些测试需要运行的Redis实例
// 可以使用 docker run -d -p 6379:6379 redis 启动

func setupTestRedis(t *testing.T) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       15, // 使用DB 15进行测试，避免影响生产数据
	})

	// 测试连接
	if err := client.Ping().Err(); err != nil {
		t.Skipf("跳过Redis测试: Redis未运行 (%v)", err)
	}

	// 清空测试数据库
	client.FlushDB()

	return client
}

// cleanupTestRedis 清理测试数据
func cleanupTestRedis(t *testing.T, client *redis.Client) {
	// 清空测试数据库
	if err := client.FlushDB().Err(); err != nil {
		t.Logf("清理Redis数据失败: %v", err)
	}
	client.Close()
}

func TestRedisStore_IncrAndGet(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "test")

	key := "counter"

	// 测试Incr
	count, err := store.Incr(key)
	if err != nil {
		t.Fatalf("Incr() error = %v", err)
	}
	if count != 1 {
		t.Errorf("Incr() = %v, want 1", count)
	}

	// 再次Incr
	count, err = store.Incr(key)
	if err != nil {
		t.Fatalf("Incr() error = %v", err)
	}
	if count != 2 {
		t.Errorf("Incr() = %v, want 2", count)
	}

	// 测试Get
	val, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if val != 2 {
		t.Errorf("Get() = %v, want 2", val)
	}
}

func TestRedisStore_IncrBy(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "test")

	key := "counter2"

	// 测试IncrBy
	count, err := store.IncrBy(key, 5)
	if err != nil {
		t.Fatalf("IncrBy() error = %v", err)
	}
	if count != 5 {
		t.Errorf("IncrBy() = %v, want 5", count)
	}

	// 再次IncrBy
	count, err = store.IncrBy(key, 3)
	if err != nil {
		t.Fatalf("IncrBy() error = %v", err)
	}
	if count != 8 {
		t.Errorf("IncrBy() = %v, want 8", count)
	}
}

func TestRedisStore_ExpireAndTTL(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "test")

	key := "expire_test"

	// 设置值
	_, err := store.Incr(key)
	if err != nil {
		t.Fatalf("Incr() error = %v", err)
	}

	// 设置过期时间
	err = store.Expire(key, 10*time.Second)
	if err != nil {
		t.Fatalf("Expire() error = %v", err)
	}

	// 检查TTL
	ttl, err := store.TTL(key)
	if err != nil {
		t.Fatalf("TTL() error = %v", err)
	}
	if ttl <= 0 || ttl > 10*time.Second {
		t.Errorf("TTL() = %v, want between 0 and 10s", ttl)
	}
}

func TestRedisStore_ZSetOperations(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "test")

	key := "zset_test"

	// 测试ZAdd
	err := store.ZAdd(key, 1.0, "member1")
	if err != nil {
		t.Fatalf("ZAdd() error = %v", err)
	}

	err = store.ZAdd(key, 2.0, "member2")
	if err != nil {
		t.Fatalf("ZAdd() error = %v", err)
	}

	err = store.ZAdd(key, 3.0, "member3")
	if err != nil {
		t.Fatalf("ZAdd() error = %v", err)
	}

	// 测试ZCount
	count, err := store.ZCount(key, 1.0, 3.0)
	if err != nil {
		t.Fatalf("ZCount() error = %v", err)
	}
	if count != 3 {
		t.Errorf("ZCount() = %v, want 3", count)
	}

	// 测试ZRemRangeByScore
	err = store.ZRemRangeByScore(key, 1.0, 2.0)
	if err != nil {
		t.Fatalf("ZRemRangeByScore() error = %v", err)
	}

	// 再次计数
	count, err = store.ZCount(key, 1.0, 3.0)
	if err != nil {
		t.Fatalf("ZCount() error = %v", err)
	}
	if count != 1 {
		t.Errorf("ZCount() after remove = %v, want 1", count)
	}
}

func TestRedisStore_Prefix(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "myapp")

	key := "test"

	// 设置值
	_, err := store.Incr(key)
	if err != nil {
		t.Fatalf("Incr() error = %v", err)
	}

	// 直接从Redis检查key是否有前缀
	val, err := client.Get("myapp:test").Result()
	if err != nil {
		t.Fatalf("Redis Get() error = %v", err)
	}
	if val != "1" {
		t.Errorf("Redis value = %v, want 1", val)
	}

	// 检查不带前缀的key不存在
	_, err = client.Get("test").Result()
	if err != redis.Nil {
		t.Error("不带前缀的key不应该存在")
	}
}

func TestRedisStore_Eval(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "test")

	// 简单的Lua脚本测试
	script := `
		return redis.call('SET', KEYS[1], ARGV[1])
	`

	result, err := store.Eval(script, []string{"lua_test"}, "hello")
	if err != nil {
		t.Fatalf("Eval() error = %v", err)
	}

	t.Logf("Eval result: %v", result)

	// 验证值是否设置成功
	val, err := client.Get("test:lua_test").Result()
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if val != "hello" {
		t.Errorf("Get() = %v, want hello", val)
	}
}

func BenchmarkRedisStore_Incr(b *testing.B) {
	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15,
	})
	defer client.Close()

	if err := client.Ping().Err(); err != nil {
		b.Skipf("跳过基准测试: Redis未运行")
	}

	store := NewStore(client, "bench")
	key := "bench_counter"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := store.Incr(key)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// TestRedisStore_SetAndDel 测试Set和Del方法
func TestRedisStore_SetAndDel(t *testing.T) {
	client := setupTestRedis(t)
	defer cleanupTestRedis(t, client)

	store := NewStore(client, "test")
	key := "testkey"

	// 测试Set
	err := store.Set(key, 42)
	if err != nil {
		t.Fatalf("Set失败: %v", err)
	}

	// 验证Set成功
	val, err := store.Get(key)
	if err != nil {
		t.Fatalf("Get失败: %v", err)
	}
	if val != 42 {
		t.Errorf("期望值42，实际%d", val)
	}

	// 测试Del
	err = store.Del(key)
	if err != nil {
		t.Fatalf("Del失败: %v", err)
	}

	// 验证Del成功
	val, err = store.Get(key)
	if err != nil {
		t.Fatalf("Get失败: %v", err)
	}
	if val != 0 {
		t.Errorf("期望值0（已删除），实际%d", val)
	}
}
