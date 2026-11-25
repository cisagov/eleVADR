"""Opt-in waiver for missing *frozen* regression captures (Datasets 01-03).

Frozen captures are checked in as binary evidence and cannot be regenerated.
When they are not available (for example on a fresh clone), a developer may
set ``ELEVADR_ALLOW_MISSING_FROZEN=1`` to let the gate proceed.

What the waiver covers: a frozen capture that is *absent*. Nothing else.
A present capture with the wrong SHA-256, a missing generated capture, and
every other check still fail exactly as before.
"""
from __future__ import annotations

import os

ENV_VAR = "ELEVADR_ALLOW_MISSING_FROZEN"


def allow_missing_frozen() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}
