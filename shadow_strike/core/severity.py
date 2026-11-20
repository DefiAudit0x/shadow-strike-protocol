"""Canonical severity labels shared by reporting and integrations."""

SEVERITY_BY_CLASS = {
    "reentrancy": "critical",
    "oracle_manipulation": "critical",
    "flash_loan": "critical",
    "price_manipulation": "critical",
    "access_control": "high",
    "signature_replay": "high",
    "initialization": "high",
    "upgradeability": "high",
    "accounting": "medium",
    "cross_contract": "medium",
    "economic": "medium",
}

