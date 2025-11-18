package redis

import (
	"strconv"
	"time"

	"github.com/Fischlvor/go-ratelimiter"
	libredis "github.com/go-redis/redis"
)

// RedisStore Redis存储实现
type Store struct {
	client *libredis.Client
	prefix string
}

// NewRedisStore 创建Redis存储
func NewStore(client *libredis.Client, prefix string) ratelimiter.Store {
	return &Store{
		client: client,
		prefix: prefix,
	}
}

// key 添加前缀
func (s *Store) key(k string) string {
	if s.prefix == "" {
		return k
	}
	return s.prefix + ":" + k
}

// Get 获取键的值
func (s *Store) Get(key string) (int64, error) {
	val, err := s.client.Get(s.key(key)).Result()
	if err == libredis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(val, 10, 64)
}

// Incr 递增
func (s *Store) Incr(key string) (int64, error) {
	return s.client.Incr(s.key(key)).Result()
}

// IncrBy 增加指定数量
func (s *Store) IncrBy(key string, value int64) (int64, error) {
	return s.client.IncrBy(s.key(key), value).Result()
}

// Expire 设置过期时间
func (s *Store) Expire(key string, expiration time.Duration) error {
	return s.client.Expire(s.key(key), expiration).Err()
}

// TTL 获取剩余时间
func (s *Store) TTL(key string) (time.Duration, error) {
	return s.client.TTL(s.key(key)).Result()
}

// ZAdd 添加到有序集合
func (s *Store) ZAdd(key string, score float64, member string) error {
	return s.client.ZAdd(s.key(key), libredis.Z{
		Score:  score,
		Member: member,
	}).Err()
}

// ZRemRangeByScore 按分数范围删除
func (s *Store) ZRemRangeByScore(key string, min, max float64) error {
	minStr := strconv.FormatFloat(min, 'f', -1, 64)
	maxStr := strconv.FormatFloat(max, 'f', -1, 64)
	return s.client.ZRemRangeByScore(s.key(key), minStr, maxStr).Err()
}

// ZCount 统计分数范围内的成员数量
func (s *Store) ZCount(key string, min, max float64) (int64, error) {
	minStr := strconv.FormatFloat(min, 'f', -1, 64)
	maxStr := strconv.FormatFloat(max, 'f', -1, 64)
	return s.client.ZCount(s.key(key), minStr, maxStr).Result()
}

// Eval 执行Lua脚本
func (s *Store) Eval(script string, keys []string, args ...interface{}) (interface{}, error) {
	// 为所有key添加前缀
	prefixedKeys := make([]string, len(keys))
	for i, k := range keys {
		prefixedKeys[i] = s.key(k)
	}
	return s.client.Eval(script, prefixedKeys, args...).Result()
}
