import pytest

from argus.events import Event
from tests.detections.support import Case, fire, variants
from tests.helpers import BROWSER, web

ATTACKER = "198.18.10.10"
STUFFER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"


def logins(
    n: int, *, status: int = 401, every: float = 5, path: str = "/login", ip: str = ATTACKER
) -> list[Event]:
    return [web(path, t=i * every, ip=ip, method="POST", status=status, size=320) for i in range(n)]


def stuffing(ips: int, *, ua: str = STUFFER_UA, every: float = 20) -> list[Event]:
    return [
        web("/login", t=i * every, ip=f"198.18.30.{i}", method="POST", status=401, ua=ua)
        for i in range(ips)
    ]


CASES: dict[str, Case] = {
    "web-shell-known-name": Case(
        positives=[
            [web("/wso.php", ip=ATTACKER, status=404)],
            [web("/wp-content/plugins/x/c99.php", ip=ATTACKER, status=200)],
            [web("/alfa-rex.php7", ip=ATTACKER, status=404)],
        ],
        negatives=[
            [web("/shell-scripting-guide.html", ip=ATTACKER)],
            [web("/blog/how-the-c99-standard-changed-c", ip=ATTACKER)],
        ],
    ),
    "web-shell-upload-exec": Case(
        positives=[
            [web("/uploads/2026/03/img_4821.php?cmd=id", ip=ATTACKER, method="POST")],
            [web("/wp-content/uploads/avatar.phtml", ip=ATTACKER)],
            [web("/images/thumb.jsp", ip=ATTACKER)],
        ],
        negatives=[
            [web("/uploads/2026/03/photo.jpg", ip=ATTACKER)],
            [web("/uploads/evil.php", ip=ATTACKER, status=403)],
            [web("/index.php", ip=ATTACKER)],
        ],
    ),
    "web-login-brute-force": Case(
        positives=[
            logins(15),
            logins(60, every=1, path="/wp-login.php", status=200),
            logins(20, path="/api/v1/auth/login", status=403),
        ],
        negatives=[
            logins(14),
            [*logins(2), *[web("/login", t=20, ip=ATTACKER, method="POST", status=302)]],
            logins(30, every=30),
            logins(40, status=401, path="/search"),
        ],
    ),
    "web-credential-stuffing": Case(
        positives=[stuffing(8), stuffing(40, every=5)],
        negatives=[
            stuffing(7),
            stuffing(20, every=90),
            [
                web("/login", t=i * 30, ip=f"198.18.31.{i}", method="POST", status=302, ua=BROWSER)
                for i in range(30)
            ],
        ],
    ),
    "web-request-flood": Case(
        positives=[
            [web(f"/search?q={i}", t=i * 0.1, ip=ATTACKER) for i in range(300)],
        ],
        negatives=[
            [web(f"/page/{i}", t=i * 0.25, ip=ATTACKER) for i in range(299)],
            [web(f"/page/{i}", t=i * 0.21, ip=ATTACKER) for i in range(600)],
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


def test_stuffing_alert_names_every_participating_address() -> None:
    (alert,) = fire("web-credential-stuffing", stuffing(12))
    assert len(alert.actors) == 12
    assert alert.group == (("user_agent", STUFFER_UA),)
