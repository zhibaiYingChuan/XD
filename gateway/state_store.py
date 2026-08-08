"""
Redis 共享状态存储 — 多实例水平扩展核心

用途:
  1. 安全原型库共享（safe_prototypes 跨实例同步）
  2. 会话信任状态（session_id → trust_level 共享）
  3. 攻击统计计数（全局拦截率、模式统计）
  4. 配置状态标记（通知所有实例热加载）

架构:
  网关实例1 ────┐
  网关实例2 ────┤──→ Redis ←── 共享原型 + 会话 + 统计
  网关实例3 ────┘
"""
import json
import time
from typing import Dict, List, Optional, Any


class RedisConfig:
    """Redis 连接配置"""

    def __init__(self,
                 url: str = "redis://localhost:6379/0",
                 prefix: str = "xuandun:",
                 ttl_prototype: int = 3600 * 24,     # 原型缓存24小时
                 ttl_session: int = 3600,              # 会话状态1小时
                 ttl_stats: int = 300,                 # 统计快照5分钟
                 enabled: bool = True):
        self.url = url
        self.prefix = prefix
        self.ttl_prototype = ttl_prototype
        self.ttl_session = ttl_session
        self.ttl_stats = ttl_stats
        self.enabled = enabled


class RedisStateStore:
    """Redis 共享状态存储 — 支持多实例水平扩展

    当 Redis 不可用时优雅降级为内存模式（单实例行为）
    """

    def __init__(self, config: Optional[RedisConfig] = None):
        self._config = config or RedisConfig()
        self._redis = None
        self._fallback: Dict[str, Any] = {}  # 内存降级存储
        self._connected = False

        if self._config.enabled:
            self._try_connect()

    def _try_connect(self):
        """尝试连接 Redis，失败时降级到内存模式"""
        try:
            import redis
            self._redis = redis.Redis.from_url(
                self._config.url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=3,
            )
            self._redis.ping()
            self._connected = True
        except Exception:
            self._connected = False

    def _key(self, namespace: str, identifier: str) -> str:
        return f"{self._config.prefix}{namespace}:{identifier}"

    # ── 原型共享 ──

    def store_prototype(self, text: str, label: str, vector: Optional[List[float]] = None):
        """存储安全/攻击原型到共享存储"""
        entry = {
            "text": text[:500],
            "label": label,
            "stored_at": time.time(),
        }
        if vector:
            entry["vector"] = vector

        key = self._key("prototype", f"{label}:{hash(text) % 100000}")

        if self._connected and self._redis:
            self._redis.setex(key, self._config.ttl_prototype, json.dumps(entry))
        else:
            self._fallback[key] = entry

    def get_prototypes(self, label: str = "safe", limit: int = 100) -> List[str]:
        """获取指定标签的原型文本列表"""
        pattern = self._key("prototype", f"{label}:*")
        results = []

        if self._connected and self._redis:
            keys = list(self._redis.scan_iter(match=pattern, count=limit))
            for k in keys[:limit]:
                raw = self._redis.get(k)
                if raw:
                    try:
                        entry = json.loads(raw)
                        results.append(entry.get("text", ""))
                    except json.JSONDecodeError:
                        pass
        else:
            for k, v in self._fallback.items():
                if pattern.replace("*", "") in k and len(results) < limit:
                    results.append(v.get("text", ""))

        return results

    # ── 会话状态 ──

    def store_session(self, session_id: str, data: Dict):
        """存储会话状态"""
        key = self._key("session", session_id)
        entry = {**data, "updated_at": time.time()}

        if self._connected and self._redis:
            self._redis.setex(key, self._config.ttl_session, json.dumps(entry))
        else:
            self._fallback[key] = entry

    def get_session(self, session_id: str) -> Optional[Dict]:
        """获取会话状态"""
        key = self._key("session", session_id)

        if self._connected and self._redis:
            raw = self._redis.get(key)
            if raw:
                return json.loads(raw)
        else:
            return self._fallback.get(key)

        return None

    # ── 全局统计 ──

    def incr_counter(self, counter_name: str, amount: int = 1):
        """递增全局计数器"""
        key = self._key("counter", counter_name)

        if self._connected and self._redis:
            self._redis.incrby(key, amount)
            self._redis.expire(key, self._config.ttl_stats)
        else:
            self._fallback[key] = self._fallback.get(key, 0) + amount

    def get_counter(self, counter_name: str) -> int:
        """获取全局计数器值"""
        key = self._key("counter", counter_name)

        if self._connected and self._redis:
            val = self._redis.get(key)
            return int(val) if val else 0
        return self._fallback.get(key, 0)

    def get_all_counters(self) -> Dict[str, int]:
        """获取所有计数器"""
        results = {}
        pattern = self._key("counter", "*")

        if self._connected and self._redis:
            keys = self._redis.scan_iter(match=pattern)
            for k in keys:
                name = k.replace(self._key("counter", ""), "")
                val = self._redis.get(k)
                results[name] = int(val) if val else 0
        else:
            for k, v in self._fallback.items():
                if "counter" in k:
                    name = k.replace(self._key("counter", ""), "")
                    results[name] = v

        return results

    # ── 状态查询 ──

    def get_status(self) -> Dict:
        """获取共享存储状态"""
        return {
            "backend": "redis" if self._connected else "memory",
            "connected": self._connected,
            "counter_keys": len(self.get_all_counters()),
            "is_shared": self._connected,  # 只有 Redis 模式下才是真正的多实例共享
        }

    def close(self):
        """关闭连接"""
        if self._connected and self._redis:
            try:
                self._redis.close()
            except Exception:
                pass
            self._connected = False
