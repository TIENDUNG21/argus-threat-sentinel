"""Benign traffic, including the awkward cases a detector must not trip over:
SQL-sounding searches, crawlers that touch many paths, an uptime monitor, an
office NAT, admins who mistype passwords, a user logging in while travelling,
and (in some seeds) an admin who logs in as root."""

from __future__ import annotations

from datetime import datetime, timedelta
from urllib.parse import quote_plus

from argus.simulate.world import (
    API_UA,
    ASSETS_FIRST,
    BLOG_POSTS,
    BROWSERS,
    CRAWLERS,
    IMAGES,
    MONITOR_UA,
    PRODUCTS,
    SEARCH_TERMS,
    SSH_ADMINS,
    STATIC_PAGES,
    World,
    daytime_hour,
)

PAGES = STATIC_PAGES + BLOG_POSTS + PRODUCTS
REFERRERS = (
    "",
    "",
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://news.example.com/",
)
UIDS = {"root": 0, "alice": 1001, "bob": 1002, "carol": 1003, "deploy": 1100, "backup": 1101}


def browse(world: World, ip: str, ua: str, t: datetime) -> datetime:
    """One browsing session starting at ``t``; returns when it ended."""
    rng = world.rng
    referrer = rng.choice(REFERRERS)
    pages = [rng.choice(("/", "/", *BLOG_POSTS, *PRODUCTS[:12]))]
    pages += [rng.choice(PAGES) for _ in range(rng.randint(1, 9))]
    for number, page in enumerate(pages):
        broken = rng.random() < 0.03
        target = f"/blog/archive-{rng.randint(2015, 2019)}" if broken else page
        status = 404 if broken else 200
        world.hit(
            t, ip, target, status=status, size=rng.randint(6000, 42000), referrer=referrer, ua=ua
        )
        asset_t = t
        assets = list(ASSETS_FIRST) if number == 0 else []
        assets += rng.sample(IMAGES, rng.randint(0, 3))
        for asset in assets:
            asset_t += timedelta(milliseconds=rng.randint(20, 400))
            cached = number > 0 and rng.random() < 0.6
            world.hit(
                asset_t,
                ip,
                asset,
                status=304 if cached else 200,
                size=0 if cached else rng.randint(800, 90000),
                referrer="https://shop.example" + page,
                ua=ua,
            )
        referrer = "https://shop.example" + page
        t += timedelta(seconds=rng.uniform(5, 90))
    if rng.random() < 0.12:
        term = quote_plus(rng.choice(SEARCH_TERMS))
        world.hit(
            t, ip, f"/search?q={term}", size=rng.randint(4000, 20000), referrer=referrer, ua=ua
        )
        t += timedelta(seconds=rng.uniform(5, 40))
    if rng.random() < 0.08:
        t = login(world, ip, ua, t)
    return t


def login(world: World, ip: str, ua: str, t: datetime) -> datetime:
    rng = world.rng
    world.hit(t, ip, "/login", size=5200, ua=ua)
    t += timedelta(seconds=rng.uniform(4, 15))
    for _ in range(rng.choice((0, 0, 0, 0, 0, 1, 1, 2))):
        world.hit(t, ip, "/login", method="POST", status=401, size=5400, ua=ua)
        t += timedelta(seconds=rng.uniform(6, 25))
    world.hit(t, ip, "/login", method="POST", status=302, size=0, ua=ua)
    world.hit(t + timedelta(milliseconds=300), ip, "/account", size=9000, ua=ua)
    return t + timedelta(seconds=rng.uniform(10, 60))


def visitors(world: World, per_day: int) -> None:
    rng = world.rng
    days = -(-world.hours // 24)
    for day in range(days):
        for _ in range(per_day):
            ip = world.ips.take()
            ua = rng.choice(BROWSERS)
            world.labels.add(ip, "benign-visitor", malicious=False)
            for _ in range(rng.choice((1, 1, 1, 2, 2, 3))):
                browse(world, ip, ua, world.at(daytime_hour(world, day)))


def office(world: World) -> None:
    """Many colleagues behind one NAT address."""
    ip = world.ips.take()
    world.labels.add(ip, "benign-office-nat", malicious=False)
    days = -(-world.hours // 24)
    for day in range(days):
        for _ in range(25):
            hour = day * 24 + world.rng.uniform(8, 18)
            browse(world, ip, world.rng.choice(BROWSERS), world.at(hour))


def crawlers(world: World) -> None:
    rng = world.rng
    for ua in CRAWLERS:
        ip = world.ips.take()
        world.labels.add(ip, "benign-crawler", malicious=False)
        t = world.at(rng.uniform(0, 2))
        next_robots = t
        while t < world.end:
            if t >= next_robots:
                world.hit(t, ip, "/robots.txt", size=180, ua=ua)
                next_robots = t + timedelta(hours=6)
            elif rng.random() < 0.05:
                world.hit(t, ip, f"/products/{rng.randint(1, 99)}", status=404, size=1500, ua=ua)
            else:
                world.hit(t, ip, rng.choice(PAGES), size=rng.randint(6000, 42000), ua=ua)
            t += timedelta(seconds=rng.expovariate(1 / 150))


def monitor(world: World) -> None:
    ip = world.ips.take()
    world.labels.add(ip, "benign-uptime-monitor", malicious=False)
    t = world.at(0.01)
    while t < world.end:
        world.hit(t, ip, "/health", size=2, ua=MONITOR_UA)
        t += timedelta(seconds=60)


def api_client(world: World) -> None:
    ip = world.ips.take()
    world.labels.add(ip, "benign-api-client", malicious=False)
    t = world.at(0.1)
    while t < world.end:
        for page in range(1, 6):
            world.hit(
                t + timedelta(seconds=page), ip, f"/api/v1/items?page={page}", size=3800, ua=API_UA
            )
        t += timedelta(minutes=15)


def _ssh_login(
    world: World, t: datetime, user: str, ip: str, *, method: str = "publickey", typos: int = 0
) -> None:
    rng = world.rng
    pid = world.next_pid()
    port = world.port()
    for _ in range(typos):
        world.log(t, f"Failed password for {user} from {ip} port {port} ssh2")
        t += timedelta(seconds=rng.uniform(3, 9))
    suffix = f": ED25519 SHA256:{world.fingerprint()}" if method == "publickey" else ""
    world.log(t, f"Accepted {method} for {user} from {ip} port {port} ssh2{suffix}")
    uid = UIDS.get(user, 1500)
    world.log(t, f"pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)")
    world.log(t, f"New session {pid % 97} of user {user}.", program="systemd-logind")
    end = t + timedelta(minutes=rng.uniform(2, 90))
    world.log(end, f"Received disconnect from {ip} port {port}:11: disconnected by user")
    world.log(end, f"Disconnected from user {user} {ip} port {port}")
    world.log(end, f"pam_unix(sshd:session): session closed for user {user}")


def ssh_users(world: World) -> None:
    rng = world.rng
    days = -(-world.hours // 24)
    homes: dict[str, list[str]] = {}
    for user in SSH_ADMINS:
        homes[user] = [world.ips.take() for _ in range(rng.randint(1, 2))]
        for ip in homes[user]:
            world.labels.add(ip, "benign-ssh-admin", malicious=False)
        for day in range(days):
            for _ in range(rng.randint(1, 3)):
                typo = rng.random() < 0.12
                _ssh_login(
                    world,
                    world.at(day * 24 + rng.uniform(7, 19)),
                    user,
                    rng.choice(homes[user]),
                    method="password" if typo else "publickey",
                    typos=rng.randint(1, 2) if typo else 0,
                )

    ci = world.ips.take()
    world.labels.add(ci, "benign-ci-runner", malicious=False)
    for hour in range(0, world.hours, 2):
        _ssh_login(world, world.at(hour + rng.uniform(0, 0.5)), "deploy", ci)

    backup = world.ips.take()
    world.labels.add(backup, "benign-backup-server", malicious=False)
    for day in range(days):
        _ssh_login(world, world.at(day * 24 + 2 + rng.uniform(0, 0.2)), "backup", backup)

    if rng.random() < 0.5:
        traveller = rng.choice(SSH_ADMINS)
        hotel = world.ips.take()
        world.labels.add(hotel, "benign-ssh-travel", malicious=False)
        _ssh_login(world, world.at(rng.uniform(30, world.hours - 4)), traveller, hotel)

    if rng.random() < 0.3:
        admin = rng.choice(SSH_ADMINS)
        _ssh_login(world, world.at(rng.uniform(1, world.hours - 2)), "root", homes[admin][0])

    checker = world.ips.take()
    world.labels.add(checker, "benign-tcp-check", malicious=False)
    t = world.at(0.05)
    while t < world.end:
        world.log(t, f"Did not receive identification string from {checker} port {world.port()}")
        t += timedelta(minutes=5)

    for hour in range(world.hours):
        t = world.at(hour + 17 / 60)
        world.log(
            t,
            "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            program="CRON",
        )
