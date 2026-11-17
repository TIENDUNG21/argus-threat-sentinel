"""A small MITRE ATT&CK (Enterprise) catalog: the techniques Argus detects plus a
few that custom rules commonly need.

Each technique is listed under the tactic it most often represents in web and
SSH logs. Techniques not listed here can still be used in custom rules by
giving the rule an explicit ``tactic``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

TACTIC_ORDER: tuple[str, ...] = (
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
)
"""ATT&CK Enterprise tactics in kill-chain order."""

TACTIC_NAMES: Mapping[str, str] = MappingProxyType(
    {tactic: tactic.replace("-", " ").title().replace("And", "and") for tactic in TACTIC_ORDER}
)


@dataclass(frozen=True, slots=True)
class Technique:
    id: str
    name: str
    tactic: str


def _catalog(*items: tuple[str, str, str]) -> Mapping[str, Technique]:
    return MappingProxyType({tid: Technique(tid, name, tactic) for tid, name, tactic in items})


TECHNIQUES: Mapping[str, Technique] = _catalog(
    ("T1589", "Gather Victim Identity Information", "reconnaissance"),
    ("T1592", "Gather Victim Host Information", "reconnaissance"),
    ("T1595", "Active Scanning", "reconnaissance"),
    ("T1595.001", "Active Scanning: Scanning IP Blocks", "reconnaissance"),
    ("T1595.002", "Active Scanning: Vulnerability Scanning", "reconnaissance"),
    ("T1595.003", "Active Scanning: Wordlist Scanning", "reconnaissance"),
    ("T1078", "Valid Accounts", "initial-access"),
    ("T1078.003", "Valid Accounts: Local Accounts", "initial-access"),
    ("T1133", "External Remote Services", "initial-access"),
    ("T1190", "Exploit Public-Facing Application", "initial-access"),
    ("T1059", "Command and Scripting Interpreter", "execution"),
    ("T1505.003", "Server Software Component: Web Shell", "persistence"),
    (
        "T1548.003",
        "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "privilege-escalation",
    ),
    ("T1110", "Brute Force", "credential-access"),
    ("T1110.001", "Brute Force: Password Guessing", "credential-access"),
    ("T1110.003", "Brute Force: Password Spraying", "credential-access"),
    ("T1110.004", "Brute Force: Credential Stuffing", "credential-access"),
    ("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access"),
    ("T1552.005", "Unsecured Credentials: Cloud Instance Metadata API", "credential-access"),
    ("T1046", "Network Service Discovery", "discovery"),
    ("T1083", "File and Directory Discovery", "discovery"),
    ("T1021.004", "Remote Services: SSH", "lateral-movement"),
    ("T1071.001", "Application Layer Protocol: Web Protocols", "command-and-control"),
    ("T1048", "Exfiltration Over Alternative Protocol", "exfiltration"),
    ("T1498", "Network Denial of Service", "impact"),
    ("T1499", "Endpoint Denial of Service", "impact"),
    ("T1499.002", "Endpoint Denial of Service: Service Exhaustion Flood", "impact"),
)


def technique_url(technique_id: str) -> str:
    """Link to the technique page on attack.mitre.org."""
    return "https://attack.mitre.org/techniques/" + technique_id.replace(".", "/") + "/"


def tactic_rank(tactic: str) -> int:
    """Position of ``tactic`` in the kill chain (unknown tactics sort last)."""
    try:
        return TACTIC_ORDER.index(tactic)
    except ValueError:
        return len(TACTIC_ORDER)
