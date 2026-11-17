import pytest

from argus.events import Event
from tests.detections.support import Case, fire, variants
from tests.helpers import web

ATTACKER = "198.18.8.8"
NIKTO = "Mozilla/5.00 (Nikto/2.5.0) (Evasions:None) (Test:000001)"
SQLMAP = "sqlmap/1.8.4#stable (https://sqlmap.org)"
GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


def misses(paths: list[str], *, every: float = 2, status: int = 404) -> list[Event]:
    return [web(p, t=i * every, ip=ATTACKER, status=status) for i, p in enumerate(paths)]


WORDLIST = [f"/{word}" for word in ("admin", "backup", "old", "test", "dev", "tmp", "cgi-bin")]
WORDLIST += [f"/{word}.php" for word in ("info", "login", "panel", "config", "setup", "install")]
WORDLIST += [f"/api/v{i}" for i in range(1, 10)]

CASES: dict[str, Case] = {
    "web-scanner-user-agent": Case(
        positives=[
            [web("/", ip=ATTACKER, ua=NIKTO)],
            [web("/products?id=1", ip=ATTACKER, ua=SQLMAP)],
            [web("/", ip=ATTACKER, ua="Mozilla/5.0 (compatible; Nmap Scripting Engine)")],
        ],
        negatives=[
            [web("/", ip=ATTACKER, ua=GOOGLEBOT)],
            [web("/blog/sqlmap-and-nikto-explained", ip=ATTACKER)],
        ],
    ),
    "web-wordlist-scan": Case(
        positives=[misses(WORDLIST[:20]), misses(WORDLIST, every=0.2)],
        negatives=[
            misses(WORDLIST[:19]),
            misses(["/favicon.ico"] * 200, every=0.5),
            misses(WORDLIST, every=10),
            misses(WORDLIST, status=200),
        ],
    ),
    "web-sensitive-file-probe": Case(
        positives=[
            misses(["/.env", "/.git/config", "/backup.sql"]),
            misses(["/%2eenv", "/.aws/credentials", "/wp-config.php.bak", "/.DS_Store"]),
        ],
        negatives=[
            misses(["/.env", "/.env", "/.env"]),
            misses(["/environment", "/git/config-guide", "/docs/backup.html"]),
            misses(["/.env", "/.git/config", "/backup.sql"], every=400),
        ],
    ),
    "web-sensitive-file-exposed": Case(
        positives=[
            [web("/.env", ip=ATTACKER, status=200, size=812)],
            [web("/.git/config", ip=ATTACKER, status=200, size=233)],
        ],
        negatives=[
            [web("/.env", ip=ATTACKER, status=404, size=150)],
            [web("/.env", ip=ATTACKER, status=200, size=0)],
            [web("/phpinfo.php", ip=ATTACKER, status=200, size=80000)],
        ],
    ),
    "web-user-enumeration": Case(
        positives=[
            misses([f"/?author={i}" for i in range(1, 6)], status=301),
            misses(["/wp-json/wp/v2/users", "/?rest_route=/wp/v2/users", "/?author=1"]),
        ],
        negatives=[
            misses(["/?author=1", "/?author=1", "/?author=1"], status=301),
            misses(["/authors", "/about/team", "/blog?author_name=jane"]),
        ],
    ),
}


@pytest.mark.parametrize(("rule_id", "index"), variants(CASES, positive=True))
def test_positive_cases_fire(rule_id: str, index: int) -> None:
    alerts = fire(rule_id, CASES[rule_id].positives[index])
    assert alerts, f"{rule_id} did not fire on positive case {index}"


@pytest.mark.parametrize(("rule_id", "index"), variants(CASES, positive=False))
def test_negative_cases_stay_quiet(rule_id: str, index: int) -> None:
    assert fire(rule_id, CASES[rule_id].negatives[index]) == []


def test_wordlist_alert_counts_the_whole_burst() -> None:
    (alert,) = fire("web-wordlist-scan", misses(WORDLIST, every=0.2))
    assert alert.count == len(WORDLIST)
    assert len(alert.distinct_values) == len(WORDLIST)
