from pathlib import Path

import pytest

from argus.ml.detector import AnomalyConfig
from argus.pipeline import ScanOptions, ScanResult, scan

UA = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"


def access(ip: str, second: int, target: str, status: int = 200, ua: str = UA) -> str:
    minute, sec = divmod(second, 60)
    return (
        f'{ip} - - [02/Mar/2026:10:{minute:02d}:{sec:02d} +0000] "GET {target} HTTP/1.1" '
        f'{status} 512 "-" "{ua}"'
    )


@pytest.fixture(scope="session")
def scan_result(tmp_path_factory: pytest.TempPathFactory) -> ScanResult:
    folder: Path = tmp_path_factory.mktemp("report")
    lines = [access(f"198.18.80.{i}", i * 7 % 3000, f"/page/{i % 9}") for i in range(200)]
    lines += [
        access("198.18.81.1", 100 + s, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 400)
        for s in range(3)
    ]
    lines += [access("198.18.81.2", 200 + s, f"/x{s}", 404, ua="sqlmap/1.8") for s in range(60)]
    lines += ["garbage <b>not escaped?</b>", ""]
    auth = [
        f"2026-03-02T10:20:{s:02d}+00:00 web01 sshd[9]: Failed password for root from "
        f"198.18.81.2 port 4000 ssh2"
        for s in range(0, 30, 2)
    ]
    (folder / "access.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (folder / "auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")
    options = ScanOptions(anomaly=AnomalyConfig(min_events=1, min_actors=5))
    return scan([folder / "access.log", folder / "auth.log"], options)
