import io
from pathlib import Path

from argus.live import follow
from argus.rules.loader import builtin_rules

LINE = (
    "2026-03-02T10:00:{s:02d}+00:00 web01 sshd[1]: "
    "Failed password for root from 198.18.1.1 port 2 ssh2\n"
)


def test_follow_prints_alerts_as_they_fire(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    batches = ["".join(LINE.format(s=s) for s in range(10)), "garbage\n", ""]
    done = []

    def sleep(_: float) -> None:
        if batches:
            with log.open("a", encoding="utf-8") as handle:
                handle.write(batches.pop(0))
        else:
            done.append(True)

    out = io.StringIO()
    stats = follow(log, "sshd", builtin_rules(), out, stop=lambda: bool(done), sleep=sleep)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1
    assert "ssh-brute-force" in lines[0]
    assert "198.18.1.1" in lines[0]
    assert (stats.total_lines, stats.events, stats.malformed) == (11, 10, 1)
