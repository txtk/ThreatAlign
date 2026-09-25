"""Compatibility entrypoint for the public ThreatAlign package."""

from __future__ import annotations

import asyncio

from threatalign.run_heaa_threatalign import main as run_main


if __name__ == "__main__":
    asyncio.run(run_main())
