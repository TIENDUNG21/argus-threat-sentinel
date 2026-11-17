"""The simulated site: pages, people, address space and the record types the
generators emit. Everything random comes from one ``random.Random(seed)``.

Addresses come from ranges reserved for documentation and benchmarking
(198.18.0.0/15, RFC 2544, and 2001:db8::/32, RFC 3849), so no real host is ever
named. Benign and malicious actors draw from the same pool, so the address
itself carries no label.
"""

from __future__ import annotations

import ipaddress
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from argus.simulate.labels import Labels

BENCH_NET = ipaddress.ip_network("198.18.0.0/15")
DOC_NET6 = ipaddress.ip_network("2001:db8::/32")
CALLBACK_HOSTS = ("198.51.100.23", "203.0.113.77", "198.51.100.140")
"""Documentation addresses (RFC 5737) used as attacker callback hosts in payloads."""

BROWSERS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0",
)
CRAWLERS = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
)
MONITOR_UA = "UptimeMonitor/2.1 (status checks)"
API_UA = "python-requests/2.32.3"
SCANNER_UAS = (
    "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/118.0.0.0 Safari/537.36 "
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
)
SQLMAP_UA = "sqlmap/1.8.4#stable (https://sqlmap.org)"
NOISE_UAS = (
    "Mozilla/5.0 zgrab/0.x",
    "Go-http-client/1.1",
    "curl/7.88.1",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 Chrome/79.0.3945.88",
)

BLOG_POSTS = tuple(
    f"/blog/{slug}"
    for slug in (
        "release-notes-2026-02",
        "how-we-cut-page-load-time",
        "a-guide-to-our-api",
        "spring-collection",
        "behind-the-scenes",
        "customer-stories",
        "shipping-update",
        "faq-returns",
        "union-square-pop-up-store",
        "sql-select-basics-for-analysts",
        "script-writing-tips",
        "dropshipping-explained",
    )
)
PRODUCTS = tuple(f"/products/{n}" for n in range(101, 141))
STATIC_PAGES = ("/", "/about", "/contact", "/pricing", "/products", "/blog", "/docs", "/careers")
ASSETS_FIRST = ("/static/css/main.css", "/static/js/app.js", "/static/img/logo.svg")
IMAGES = tuple(f"/static/img/products/{n}.webp" for n in range(101, 141))
SEARCH_TERMS = (
    "running shoes",
    "union square hotels",
    "select tile colors",
    "sql select tutorial",
    "rock and roll t-shirt",
    "drop shipping",
    "script fonts",
    "where to buy",
    "or 1 night stay",
    "return policy",
    "gift card",
    "description of materials",
    "cat toys",
    "javascript tutorial",
)
SSH_ADMINS = ("alice", "bob", "carol")
SSH_SERVICE = ("deploy", "backup")
SSH_GUESSES = (
    "admin",
    "test",
    "user",
    "oracle",
    "postgres",
    "ubuntu",
    "git",
    "pi",
    "guest",
    "ftpuser",
    "mysql",
    "support",
    "dev",
    "jenkins",
    "hadoop",
    "www",
    "minecraft",
    "steam",
    "nagios",
    "ansible",
    "teamspeak",
    "student",
    "info",
    "office",
    "sales",
    "web",
    "tomcat",
    "elastic",
    "redis",
    "docker",
    "vagrant",
    "server",
    "operator",
    "backup",
    "deploy",
    "alice",
    "bob",
)
HOST = "web01"


@dataclass(frozen=True, slots=True)
class WebHit:
    ts: datetime
    ip: str
    method: str
    target: str
    status: int
    size: int
    referrer: str
    user_agent: str


@dataclass(frozen=True, slots=True)
class AuthLine:
    ts: datetime
    message: str
    program: str = "sshd"


@dataclass
class Traffic:
    web: list[WebHit] = field(default_factory=list)
    auth: list[AuthLine] = field(default_factory=list)


class IpPool:
    """Unique addresses; about 3% IPv6."""

    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.used: dict[str, None] = {}

    def take(self) -> str:
        while True:
            if self.rng.random() < 0.03:
                offset = self.rng.randrange(1, 2**32)
                candidate = str(DOC_NET6.network_address + offset)
            else:
                offset = self.rng.randrange(1, BENCH_NET.num_addresses - 1)
                candidate = str(BENCH_NET.network_address + offset)
            if candidate not in self.used:
                self.used[candidate] = None
                return candidate


@dataclass
class World:
    rng: random.Random
    start: datetime
    hours: int
    ips: IpPool
    labels: Labels
    git_exposed: bool
    traffic: Traffic = field(default_factory=Traffic)
    pid: int = 1000

    @property
    def end(self) -> datetime:
        return self.start + timedelta(hours=self.hours)

    def at(self, hour: float) -> datetime:
        return self.start + timedelta(hours=hour)

    def hit(
        self,
        ts: datetime,
        ip: str,
        target: str,
        *,
        status: int = 200,
        size: int = 0,
        method: str = "GET",
        referrer: str = "",
        ua: str = "",
    ) -> None:
        if ts < self.end:
            self.traffic.web.append(WebHit(ts, ip, method, target, status, size, referrer, ua))

    def log(self, ts: datetime, message: str, program: str = "sshd") -> None:
        if ts < self.end:
            self.traffic.auth.append(AuthLine(ts, message, program))

    def next_pid(self) -> int:
        self.pid += self.rng.randint(1, 40)
        return self.pid

    def port(self) -> int:
        return self.rng.randint(32768, 60999)

    def fingerprint(self) -> str:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        return "".join(self.rng.choice(alphabet) for _ in range(43))


DAY_WEIGHTS = (
    0.2,
    0.15,
    0.1,
    0.1,
    0.1,
    0.15,
    0.3,
    0.5,
    0.8,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    0.9,
    0.9,
    0.8,
    0.7,
    0.5,
    0.3,
)
"""Relative visits per UTC hour: a site whose audience sleeps from 00:00 to 06:00 UTC."""


def daytime_hour(world: World, day: int) -> float:
    """A random time on ``day`` (0-based), following DAY_WEIGHTS, in hours since start."""
    hour = world.rng.choices(range(24), weights=DAY_WEIGHTS)[0]
    return day * 24 + hour + world.rng.random()
