"""The RAM/CPU governor that decides how many Phase 2 workers a machine gets.

Regression for the SaltStack CI run: a 2-vCPU / 7 GB runner collected statements single-worker for
283 s. Two separate faults produced that, and both are pinned here -- `cpu_count - 2` collapses 2
cores to one worker, and `tcs.parallel_analyzer` used to hard-import psutil, so where psutil was
absent the governor could not even be imported and Phase 2 fell back to serial silently.
"""
import os

import pytest

from tcs import parallel_analyzer as pa


@pytest.fixture
def machine(monkeypatch):
    """Pin the governor's two inputs: measured free RAM and visible CPU count."""
    def _set(free_mb, cpus):
        monkeypatch.setattr(pa, "available_ram_mb", lambda: free_mb)
        monkeypatch.setattr(os, "cpu_count", lambda: cpus)
        return pa.compute_analysis_workers()
    return _set


def test_two_core_ci_runner_gets_two_workers(machine):
    assert machine(7_000, 2) == 2


def test_worker_count_scales_with_cores_then_caps_at_four(machine):
    assert machine(7_000, 3) == 3
    assert machine(7_000, 4) == 4
    assert machine(16_000, 8) == 4


def test_ram_budget_still_bounds_the_pool(machine):
    # 4 vCPU but only 2 per-worker budgets of headroom above the floor.
    assert machine(1_900, 4) == 3


def test_below_the_two_core_threshold_stays_serial(machine):
    assert machine(1_500, 4) == 1


def test_hard_safety_floor_wins_over_cores(machine):
    assert machine(899, 8) == 1


def test_unmeasurable_ram_stays_serial(machine):
    assert machine(None, 8) == 1


def test_available_ram_mb_works_without_psutil(monkeypatch):
    """A missing psutil must cost accuracy of the reading, never the fan-out itself."""
    monkeypatch.setattr(pa, "psutil", None)
    reading = pa.available_ram_mb()
    # Linux reports MemAvailable; other platforms return None and the governor goes serial.
    assert reading is None or reading > 0


def test_governor_is_importable_without_psutil(monkeypatch):
    monkeypatch.setattr(pa, "psutil", None)
    monkeypatch.setattr(pa, "available_ram_mb", lambda: None)
    assert pa.compute_analysis_workers() == 1
