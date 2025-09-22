# -*- coding: utf-8 -*-
"""
Created on Mon Sep 22 11:47:49 2025

@author: Vineet
"""

# backend/orchestrator/tier.py
import os
from dataclasses import dataclass

def _iget(name: str, default: int) -> int:
    try: return int(os.getenv(name, str(default)))
    except: return default

@dataclass(frozen=True)
class TierCaps:
    analyze_per_day: int
    chat_msgs_per_day: int
    uploads_per_day: int
    max_extract_chars: int
    max_file_mb: int

def caps_for_tier(tier: str) -> TierCaps:
    t = (tier or "demo").lower()
    if t == "demo":
        return TierCaps(
            analyze_per_day=_iget("MAX_CALLS_PER_DAY_DEMO", 3),
            chat_msgs_per_day=_iget("MAX_CALLS_PER_DAY_DEMO", 3),
            uploads_per_day=_iget("FREE_UPLOADS", 3),
            max_extract_chars=_iget("MAX_EXTRACT_CHARS_DEMO", 2000),
            max_file_mb=_iget("MAX_FILE_MB_DEMO", 2),
        )
    if t in ("pro",):
        return TierCaps(
            analyze_per_day=_iget("PRO_QUERIES_PER_DAY", 50),
            chat_msgs_per_day=_iget("MAX_CALLS_PER_DAY_PRO", 200),
            uploads_per_day=_iget("UPLOADS_PER_DAY_PAID", 50),
            max_extract_chars=_iget("MAX_EXTRACT_CHARS_PRO", 12000),
            max_file_mb=_iget("MAX_FILE_MB_PRO", 15),
        )
    if t in ("pro+", "pro_plus"):
        return TierCaps(
            analyze_per_day=_iget("PRO_QUERIES_PER_DAY", 50),
            chat_msgs_per_day=_iget("PRO_PLUS_MSGS_PER_DAY", 25),
            uploads_per_day=_iget("UPLOADS_PER_DAY_PAID", 50),
            max_extract_chars=_iget("MAX_EXTRACT_CHARS_PRO", 12000),
            max_file_mb=_iget("MAX_FILE_MB_PRO", 15),
        )
    if t == "premium":
        return TierCaps(
            analyze_per_day=_iget("PRO_QUERIES_PER_DAY", 50),
            chat_msgs_per_day=_iget("PREMIUM_MSGS_PER_DAY", 50),
            uploads_per_day=_iget("UPLOADS_PER_DAY_PAID", 50),
            max_extract_chars=_iget("MAX_EXTRACT_CHARS_PRO", 12000),
            max_file_mb=_iget("MAX_FILE_MB_PRO", 15),
        )
    return caps_for_tier("demo")
