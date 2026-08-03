from __future__ import annotations

from importlib.resources import files
import re


_PLACEHOLDER_RE = re.compile(r"__([A-Z][A-Z0-9_]*)__")


def read_daytona_script(name: str) -> str:
    return (
        files("boundarybench.daytona")
        .joinpath("scripts", name)
        .read_text(encoding="utf-8")
    )


def render_daytona_script(name: str, replacements: dict[str, str]) -> str:
    script = read_daytona_script(name)

    def replace_placeholder(match: re.Match[str]) -> str:
        key = match.group(1)
        try:
            return replacements[key]
        except KeyError as exc:
            raise ValueError(
                f"unknown placeholder __{key}__ in Daytona script {name}"
            ) from exc

    return _PLACEHOLDER_RE.sub(replace_placeholder, script).strip()
