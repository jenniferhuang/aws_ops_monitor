"""Command-line entry point for one-shot or recurring local collection."""

from __future__ import annotations

import argparse
from dataclasses import replace
import logging
from pathlib import Path
import signal
from threading import Event

from .collector import Collector
from .config import Config, ConfigError
from .models import HealthState
from .store import MetricStore


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Collect private AWS host and Xray metrics")
    parser.add_argument("--once", action="store_true", help="collect once and exit")
    parser.add_argument("--database", type=Path, help="override the SQLite database path")
    parser.add_argument("--interval", type=float, help="override the interval in seconds")
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
        default="INFO",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        config = Config.from_env()
        overrides: dict[str, object] = {}
        if args.database is not None:
            overrides["database_path"] = args.database
        if args.interval is not None:
            overrides["interval_seconds"] = args.interval
        if overrides:
            config = replace(config, **overrides)
    except ConfigError as exc:
        _parser().error(str(exc))

    with MetricStore(config.database_path, file_mode=config.database_file_mode) as store:
        collector = Collector(config, store)
        if args.once:
            result = collector.collect_once()
            required_states = [result.host_state]
            if config.xray_enabled:
                required_states.append(result.xray_state)
            return 1 if HealthState.UNAVAILABLE in required_states else 0

        stop = Event()

        def request_stop(_signum: int, _frame: object) -> None:
            stop.set()

        signal.signal(signal.SIGINT, request_stop)
        signal.signal(signal.SIGTERM, request_stop)
        collector.run_forever(stop)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
