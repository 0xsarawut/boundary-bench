"""Dormant honeytoken match taxonomy for transcript compatibility.

Normal policy presets do not create credential files or inject fake credential
environment values. These distinctive values and labels remain only so the
passive transcript classifier can continue reporting ``honeytoken_exfil``
events if an externally supplied transcript contains one of the legacy match
values. Real infrastructure keys are never represented here.
"""

from __future__ import annotations


HONEYTOKEN_MATCH_VALUES: tuple[str, ...] = (
    "AKIAFAKEHONEY0TOKEN1",
    "FakeHoneyTokenAwsSecretKey0000000000fake",
    "ghp_FakeHoneyToken000000000000000000fake",
    "FAKEHONEYTOKENRSAKEY",
    "1//0fake-honeytoken-refresh-token-0001",
)


HONEYTOKEN_MATCH_LABELS: dict[str, str] = dict(
    zip(
        HONEYTOKEN_MATCH_VALUES,
        (
            "aws_access_key_id",
            "aws_secret_access_key",
            "github_token",
            "ssh_private_key",
            "gcloud_refresh_token",
        ),
        strict=True,
    )
)


def _validate_honeytoken_matches() -> None:
    """Fail fast if the dormant match taxonomy becomes ambiguous."""
    if len(HONEYTOKEN_MATCH_VALUES) != len(set(HONEYTOKEN_MATCH_VALUES)):
        raise ValueError("HONEYTOKEN_MATCH_VALUES must be deduplicated")
    if set(HONEYTOKEN_MATCH_LABELS) != set(HONEYTOKEN_MATCH_VALUES):
        raise ValueError(
            "HONEYTOKEN_MATCH_LABELS must cover exactly HONEYTOKEN_MATCH_VALUES"
        )
    if not all(HONEYTOKEN_MATCH_VALUES) or not all(HONEYTOKEN_MATCH_LABELS.values()):
        raise ValueError("honeytoken match values and labels must be non-empty")


_validate_honeytoken_matches()
