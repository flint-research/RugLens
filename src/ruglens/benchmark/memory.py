"""Cross-platform peak resident-set measurement."""

from __future__ import annotations

import ctypes
import importlib
import platform
from typing import Any, cast


def peak_rss_mb() -> float:
    """Return peak RSS of the current process in MiB, or 0 when unavailable."""
    system = platform.system()
    if system == "Windows":
        try:

            class ProcessMemoryCounters(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_uint32),
                    ("page_fault_count", ctypes.c_uint32),
                    ("peak_working_set_size", ctypes.c_size_t),
                    ("working_set_size", ctypes.c_size_t),
                    ("quota_peak_paged_pool_usage", ctypes.c_size_t),
                    ("quota_paged_pool_usage", ctypes.c_size_t),
                    ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
                    ("quota_non_paged_pool_usage", ctypes.c_size_t),
                    ("pagefile_usage", ctypes.c_size_t),
                    ("peak_pagefile_usage", ctypes.c_size_t),
                ]

            win_dll = getattr(ctypes, "Win" + "DLL")
            kernel32 = win_dll("kernel32")
            psapi = win_dll("psapi")
            counters = ProcessMemoryCounters()
            counters.cb = ctypes.sizeof(ProcessMemoryCounters)
            handle = kernel32.GetCurrentProcess()
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return float(counters.peak_working_set_size) / (1024 * 1024)
        except (AttributeError, OSError, ValueError):
            return 0.0
        return 0.0
    try:
        resource = cast(Any, importlib.import_module("resource"))
        usage = resource.getrusage(resource.RUSAGE_SELF)
        max_rss = float(usage.ru_maxrss)
    except (ImportError, AttributeError, OSError, ValueError):
        return 0.0
    divisor = 1024 * 1024 if system == "Darwin" else 1024
    return max_rss / divisor
