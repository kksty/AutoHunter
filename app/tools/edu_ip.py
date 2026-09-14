"""IP / 域名 → 资产归属。

写报告时把目标反查成单位名 + 归属证明（Issue #53）。优先使用镜像内置的
仅查询 https://www.ip138.com/iplookup.php?ip=…&action=2 。

- 只查 IPv4；IPv6 直接无归属。
- 在线结果按 IP 缓存，详情页和列表后台预热不重复查询。
- school_name_no_dns / peek 只读 ip138 内存缓存，绝不在列表接口里同步打网。
- 失败一律返回 None，不影响主流程。
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import threading
import time
from functools import lru_cache
from urllib.parse import quote

import httpx

from app.http_defaults import BROWSER_UA

_IP138_URL = "https://www.ip138.com/iplookup.php"
_MIN_INTERVAL = 0.45
_HTTP_TIMEOUT = 8.0

_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()
_negative_cache: dict[str, float] = {}
_inflight: dict[str, threading.Event] = {}
_inflight_lock = threading.Lock()
_rate_lock = threading.Lock()
_last_fetch_at = 0.0
_NEGATIVE_CACHE_TTL = float(os.environ.get("AUTOHUNTER_OWNER_NEGATIVE_TTL", "900"))

_JUNK_RE = re.compile(r"html\.join|function\s*\(|^\s*'\+")
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<script\b.*?</script>", re.I | re.S)
_ROW_RE = re.compile(
    r'<td class="th">(.*?)</td>\s*<td>(.*?)</td>',
    re.I | re.S,
)
_SUFFIX_RE = re.compile(
    r"(教育网.*|无线.*|宿舍.*|公寓.*|校区.*|分校.*|学生.*|住宅.*|机房.*|"
    r"实验室.*|中心.*|研究院.*|研究生院.*|附属中学.*|附中.*|\(.*\)|（.*）).*$"
)


def _host_from_target(target: str) -> str | None:
    t = (target or "").strip()
    if not t:
        return None
    from app.urlnorm import ensure_scheme, safe_hostname
    host = safe_hostname(ensure_scheme(t))
    return host or None


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


@lru_cache(maxsize=8192)
def _resolve_host(host: str) -> str | None:
    if _is_ip(host):
        return host
    try:
        infos = socket.getaddrinfo(host, None, family=socket.AF_INET)
        for info in infos:
            return info[4][0]
    except Exception:
        return None
    return None


def _plain(html: str) -> str:
    text = _SCRIPT_RE.sub("", html or "")
    text = _TAG_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def _is_junk(value: str) -> bool:
    return bool(_JUNK_RE.search(value or ""))


def parse_ip138_html(html: str) -> dict | None:
    """解析 ip138 查询页。供单测直接喂 HTML，不打网。"""
    fields: dict[str, str] = {}
    for raw_k, raw_v in _ROW_RE.findall(html or ""):
        key = _plain(raw_k)
        val = _plain(raw_v)
        if not key or not val or _is_junk(val):
            continue
        fields[key] = val
    location = fields.get("ASN归属地") or fields.get("归属地") or ""
    isp = fields.get("运营商") or ""
    tag = fields.get("标记") or ""
    ip_type = fields.get("iP类型") or fields.get("IP类型") or ""
    if not any((location, isp, tag, ip_type)):
        return None
    return {
        "location": location,
        "isp": isp,
        "tag": tag,
        "ip_type": ip_type,
    }


def _split_location(loc: str) -> tuple[str, str]:
    parts = [p for p in (loc or "").split() if p]
    if not parts:
        return "", ""
    if parts[0] in {"中国", "美国", "日本", "韩国", "英国", "德国", "法国", "新加坡", "澳大利亚"}:
        parts = parts[1:]
    province = parts[0] if parts else ""
    city = parts[1] if len(parts) > 1 else ""
    return province, city


def _clean_school_name(name: str | None) -> str | None:
    if not name:
        return None
    s = name.strip()
    m = re.search(r"^(.*?(?:大学|学院|学校))", s)
    base = m.group(1) if m else _SUFFIX_RE.sub("", s)
    base = base.strip()
    return base or s


def _format_proof(ip: str, raw: dict) -> str:
    bits = [f"IP {ip} 经 ip138 查询"]
    if raw.get("tag"):
        bits.append(f"标记「{raw['tag']}」")
    if raw.get("isp"):
        bits.append(f"运营商{raw['isp']}")
    if raw.get("location"):
        bits.append(f"ASN归属地{raw['location']}")
    if raw.get("ip_type"):
        bits.append(f"类型{raw['ip_type']}")
    if len(bits) == 1:
        return ""
    return "，".join(bits)


def _info_from_raw(ip: str, raw: dict) -> dict:
    tag = (raw.get("tag") or "").strip()
    province, city = _split_location(raw.get("location") or "")
    return {
        "school": _clean_school_name(tag) if tag else None,
        "school_full": tag or (raw.get("isp") or ""),
        "province": province,
        "city": city,
        "ip": ip,
        "isp": raw.get("isp") or "",
        "location": raw.get("location") or "",
        "ip_type": raw.get("ip_type") or "",
        "source": "ip138",
        "proof": _format_proof(ip, raw),
    }


def _cache_get(ip: str) -> dict | None:
    with _cache_lock:
        hit = _cache.get(ip)
    return None if hit is None else dict(hit)


def _cache_put(ip: str, info: dict) -> None:
    with _cache_lock:
        _cache[ip] = dict(info)


def cache_clear() -> None:
    with _cache_lock:
        _cache.clear()
        _negative_cache.clear()
    _resolve_host.cache_clear()


def _negative_cache_hit(ip: str) -> bool:
    now = time.monotonic()
    with _cache_lock:
        expires_at = _negative_cache.get(ip)
        if expires_at is None:
            return False
        if expires_at <= now:
            _negative_cache.pop(ip, None)
            return False
        return True


def _negative_cache_put(ip: str) -> None:
    with _cache_lock:
        _negative_cache[ip] = time.monotonic() + max(0.0, _NEGATIVE_CACHE_TTL)


def _rate_limit() -> None:
    global _last_fetch_at
    with _rate_lock:
        wait = _MIN_INTERVAL - (time.monotonic() - _last_fetch_at)
        if wait > 0:
            time.sleep(wait)
        _last_fetch_at = time.monotonic()


def _ip138_disabled() -> bool:
    return os.environ.get("AUTOHUNTER_DISABLE_IP138", "").strip().lower() in {"1", "true", "yes"}


def _fetch_ip138(ip: str) -> dict | None:
    if _ip138_disabled():
        return None
    _rate_limit()
    try:
        with httpx.Client(timeout=_HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = client.get(
                _IP138_URL,
                params={"ip": ip, "action": "2"},
                headers={
                    "User-Agent": BROWSER_UA,
                    "Referer": "https://www.ip138.com/",
                    "Accept": "text/html,application/xhtml+xml",
                },
            )
            resp.raise_for_status()
            return parse_ip138_html(resp.text)
    except Exception:
        return None


def source_url(ip: str) -> str:
    return f"{_IP138_URL}?ip={quote(ip, safe='.')}&action=2"


def _lookup_ip(ip: str) -> dict | None:
    """查单个 IPv4。

    成功结果长期缓存在进程内；失败结果只缓存一小段时间，避免 ip138 不可用时
    每次打开详情都重复打满超时。并发请求同一 IP 时只允许一个线程真正访问外网。
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if ip_obj.version != 4:
        return None
    cached = _cache_get(ip)
    if cached is not None:
        return cached or None
    if _negative_cache_hit(ip):
        return None

    with _inflight_lock:
        event = _inflight.get(ip)
        if event is None:
            event = threading.Event()
            _inflight[ip] = event
            leader = True
        else:
            leader = False
    if not leader:
        event.wait(timeout=_HTTP_TIMEOUT + 2.0)
        return _cache_get(ip)

    try:
        raw = _fetch_ip138(ip)
        if raw is None:
            _negative_cache_put(ip)
            return None
        info = _info_from_raw(ip, raw)
        _cache_put(ip, info)
        return info
    finally:
        with _inflight_lock:
            _inflight.pop(ip, None)
            event.set()


def peek_cached(target: str) -> dict | None:
    """只读 ip138 内存缓存：目标本身是 IPv4 时返回。不做 DNS、不打网。"""
    host = _host_from_target(target)
    if not host or not _is_ip(host):
        return None
    try:
        if ipaddress.ip_address(host).version != 4:
            return None
    except ValueError:
        return None
    return _cache_get(host) or None


def lookup_school(target: str) -> dict | None:
    """输入 target_url / 域名 / IP，返回归属 dict 或 None。

    school      = 清洗后的单位名（ip138「标记」，如「清华大学」）
    school_full = 原始标记
    proof       = 可直接写进报告的归属证明
    """
    host = _host_from_target(target)
    if not host:
        return None
    # 无点号的假主机（测试用 http://x）不走 DNS，避免列表接口被解析拖死。
    if not _is_ip(host) and "." not in host and host != "localhost":
        return None
    ip = _resolve_host(host)
    if not ip:
        return None
    return _lookup_ip(ip)


async def lookup_school_async(target: str, timeout: float = 8.0) -> dict | None:
    """事件循环安全版。先 peek 缓存；未命中则 DNS + ip138 放线程池。"""
    import asyncio

    try:
        cached = peek_cached(target)
        if cached is not None:
            return cached
        host = _host_from_target(target)
        if host and _is_ip(host):
            try:
                if ipaddress.ip_address(host).version != 4:
                    return None
            except ValueError:
                return None
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(None, lookup_school, target), timeout=timeout
        )
    except Exception:
        return None


def school_name_no_dns(target: str) -> str | None:
    """只读 ip138 内存缓存，不做 DNS、不打网，列表接口可安全调用。"""
    info = peek_cached(target)
    return (info or {}).get("school") or None
