package dns

import (
	"sync"
	"time"
)

// cache 是纯内存、TTL 驱动、重启重取的 DNS 缓存(承设计 §10.1:分片锁、非字节路径、绝不落盘)。
type cache struct {
	shards [256]shard
}

type shard struct {
	mu sync.Mutex
	m  map[qkey]entry
}

type entry struct {
	raw      []byte // 缓存的完整应答报文(txid 命中时就地改写)
	expireAt time.Time
}

func newCache() *cache {
	c := &cache{}
	for i := range c.shards {
		c.shards[i].m = make(map[qkey]entry)
	}
	return c
}

// shardOf 用域名首字节散列到分片(简单、够均匀;非字节路径不苛求)。
func (c *cache) shardOf(k qkey) *shard {
	var h byte
	if len(k.name) > 0 {
		h = k.name[len(k.name)-1]
	}
	h ^= byte(k.qtype)
	return &c.shards[h]
}

// get 返回未过期的缓存应答的副本(命中);过期即删。
func (c *cache) get(k qkey) ([]byte, bool) {
	s := c.shardOf(k)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[k]
	if !ok {
		return nil, false
	}
	if time.Now().After(e.expireAt) {
		delete(s.m, k)
		return nil, false
	}
	return append([]byte(nil), e.raw...), true
}

// put 写入一条缓存(ttl 秒;ttl=0 不缓存)。
func (c *cache) put(k qkey, raw []byte, ttlSec uint32) {
	if ttlSec == 0 {
		return
	}
	s := c.shardOf(k)
	s.mu.Lock()
	s.m[k] = entry{
		raw:      append([]byte(nil), raw...),
		expireAt: time.Now().Add(time.Duration(ttlSec) * time.Second),
	}
	s.mu.Unlock()
}
