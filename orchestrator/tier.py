# -*- coding: utf-8 -*-
from dataclasses import dataclass

@dataclass
class Caps:
    max_messages_per_day: int | None
    max_analyzes_per_day: int | None
    max_extract_chars: int
    max_files_per_message: int
    max_file_size_mb: int

def caps_for_tier(tier: str) -> Caps:
    t = (tier or "demo").lower()

    if t in ("admin", "premium"):
        return Caps(
            max_messages_per_day=None,      # unlimited
            max_analyzes_per_day=None,      # unlimited
            max_extract_chars=120_000,
            max_files_per_message=8,
            max_file_size_mb=25,
        )

    if t in ("pro_plus", "pro+"):
        return Caps(
            max_messages_per_day=80,
            max_analyzes_per_day=30,
            max_extract_chars=80_000,
            max_files_per_message=1,
            max_file_size_mb=20,
        )

    if t == "pro":
        return Caps(
            max_messages_per_day=50,
            max_analyzes_per_day=15,
            max_extract_chars=60_000,
            max_files_per_message=1,
            max_file_size_mb=15,
        )

    # demo / trial
    return Caps(
        max_messages_per_day=15,
        max_analyzes_per_day=5,
        max_extract_chars=30_000,
        max_files_per_message=1,
        max_file_size_mb=10,
    )
