-- Copyright 2026 重庆半格智能科技有限公司
-- SPDX-License-Identifier: AGPL-3.0-only

-- Tellomi（ADR-0070 P2）：给一个计数键加 1；键是这一下才建出来的，就同时设好过期时间。
-- INCR 和 EXPIRE 在同一个脚本里执行，不会出现「加了 1、却没设过期」的键：计数键必须在 24 小时内过期（ADR-0070 §6.2）。
--
-- KEYS[1] = 计数键
-- ARGV[1] = 过期秒数
-- 返回加 1 之后的值

local count = redis.call("INCR", KEYS[1])

if count == 1 then
    redis.call("EXPIRE", KEYS[1], tonumber(ARGV[1]))
end

return count
