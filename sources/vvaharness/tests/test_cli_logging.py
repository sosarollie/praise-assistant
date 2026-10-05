# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the logging-initialisation region of vvaharness.cli.

Before this region existed, every ``log.info``/``log.debug`` call a pipeline
stage makes was silently dropped, and every ``log.warning``/``log.error`` call
fell through to Python's built-in last-resort handler. The region that fixes
that is ``cli._configure_logging(args)``, which parses and strips
``--log-level``/``--log-file`` out of argv (the three hand-rolled subcommand
parsers do not declare them) and delegates to ``util.logs.configure()``.

``configure()`` deliberately does **not** call ``logging.basicConfig`` and does
not touch the root logger. It attaches one redacting handler to the
``vvaharness`` logger and sets ``propagate = False``, so:

* a library consumer's own root handler cannot double every one of our lines;
* nothing we log can be reformatted or re-routed by whatever the embedding
  application configured on root;
* the channel is *off* until a level is supplied — via the flag or via
  ``VVAHARNESS_LOG_LEVEL`` — rather than defaulting to a configured WARNING.

Off-by-default is visibly equivalent to a WARNING default: with no handler on
the ``vvaharness`` logger and propagation still intact, a WARNING record reaches
either the embedder's root handler or Python's last-resort handler exactly as it
did before this region existed. ``test_default_settings_leave_stderr_bytes_
unchanged`` pins that.

Fully offline/deterministic: no network, no real LLM call (the shared
``stub_prompt`` fixture and network guard from conftest.py apply here too).

The ``vvaharness`` logger is process-wide state and ``configure()`` sets
``propagate = False`` on it, which would break ``caplog`` in sibling test files
if it leaked. Every test therefore runs with a private, reset ``vvaharness``
logger and gets the original restored on teardown.
"""
from __future__ import annotations

import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from vvaharness import cli
from vvaharness.util import logs
from fixtures.ctx_builders import make_taint_multi_ctx

_PKG_LOGGER = "vvaharness"


@pytest.fixture(autouse=True)
def _restore_vvaharness_logger():
    """Save/restore the ``vvaharness`` logger (and root) so nothing this file
    does to global logging state leaks to other test files.

    Deliberately does NOT reset the logger here in the fixture body: pytest's
    own logging plugin attaches its per-test ``LogCaptureHandler`` between
    fixture setup and the test call, so resetting during setup would just be
    undone before the test function runs. Each test calls ``_reset_channel``
    itself, at the top of the test body, to get exactly the state a freshly
    started process would have."""
    log = logging.getLogger(_PKG_LOGGER)
    saved_handlers, saved_level, saved_propagate = log.handlers[:], log.level, log.propagate
    saved_root_handlers, saved_root_level = logging.root.handlers[:], logging.root.level
    yield
    _close_our_handlers()
    log.handlers = saved_handlers
    log.setLevel(saved_level)
    log.propagate = saved_propagate
    logging.root.handlers = saved_root_handlers
    logging.root.setLevel(saved_root_level)


def _close_our_handlers():
    """Close file handlers ``configure()`` opened, so --log-file tests leak no fds."""
    for handler in logging.getLogger(_PKG_LOGGER).handlers:
        if getattr(handler, "_vvaharness", False) and isinstance(handler, logging.FileHandler):
            handler.close()


def _reset_channel():
    """Put the ``vvaharness`` logger back to its import-time, never-configured state."""
    log = logging.getLogger(_PKG_LOGGER)
    _close_our_handlers()
    log.handlers = []
    log.setLevel(logging.NOTSET)
    log.propagate = True


def _our_handlers() -> list[logging.Handler]:
    """The handlers ``configure()`` installed — it marks them, so they are identifiable."""
    return [h for h in logging.getLogger(_PKG_LOGGER).handlers
            if getattr(h, "_vvaharness", False)]


def _channel_is_off() -> bool:
    log = logging.getLogger(_PKG_LOGGER)
    return not _our_handlers() and log.level == logging.NOTSET and log.propagate


def _decompose_cfg():
    return SimpleNamespace(
        step3=SimpleNamespace(),
        models=SimpleNamespace(decompose="stub-model"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Level resolution (from VVAHARNESS_LOG_LEVEL, via the CLI region)
# ─────────────────────────────────────────────────────────────────────────────
def test_no_level_configured_leaves_the_channel_off(monkeypatch):
    # Ours is opt-in: with no level from either source there is no handler and
    # no level, so a WARNING still reaches root/last-resort untouched (see
    # test_default_settings_leave_stderr_bytes_unchanged).
    monkeypatch.delenv("VVAHARNESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()
    assert cli._configure_logging([]) == []
    assert _channel_is_off()


def test_level_comes_from_the_env_var(monkeypatch):
    monkeypatch.setenv("VVAHARNESS_LOG_LEVEL", "DEBUG")
    _reset_channel()
    cli._configure_logging([])
    assert logging.getLogger(_PKG_LOGGER).level == logging.DEBUG
    assert len(_our_handlers()) == 1


@pytest.mark.parametrize("value", ["info", "INFO", "Info", "  info  "])
def test_level_resolution_is_case_insensitive(monkeypatch, value):
    monkeypatch.setenv("VVAHARNESS_LOG_LEVEL", value)
    _reset_channel()
    cli._configure_logging([])
    assert logging.getLogger(_PKG_LOGGER).level == logging.INFO


def test_unrecognised_level_leaves_the_channel_off_and_says_so(monkeypatch, capsys):
    # "NOT_A_REAL_LEVEL" resolves via getattr(logging, ...) to nothing. Ours
    # must not raise, must not half-configure, and must tell the user which
    # values it accepts.
    monkeypatch.setenv("VVAHARNESS_LOG_LEVEL", "NOT_A_REAL_LEVEL")
    _reset_channel()
    cli._configure_logging([])
    err = capsys.readouterr().err
    assert _channel_is_off()
    assert "unknown log level" in err
    for level in logs.LEVELS:
        assert level in err


def test_a_same_named_non_level_module_attribute_is_rejected(monkeypatch, capsys):
    # `logging.BASIC_FORMAT` exists on the module but is a str, not a level.
    # getattr(logging, "BASIC_FORMAT", ...) resolves to it, so the
    # isinstance(..., int) guard in configure() is what stops a string being
    # handed to setLevel(). The channel must stay off rather than half-attach.
    monkeypatch.setenv("VVAHARNESS_LOG_LEVEL", "BASIC_FORMAT")
    _reset_channel()
    cli._configure_logging([])
    assert _channel_is_off()
    assert "unknown log level" in capsys.readouterr().err


# ─────────────────────────────────────────────────────────────────────────────
# Exactly one place in the whole package configures logging (the acceptance bar
# for "no logging framework, no config file, no per-module handlers").
# ─────────────────────────────────────────────────────────────────────────────
def test_util_logs_is_the_only_place_the_package_configures_logging():
    pkg_root = Path(cli.__file__).parent
    sources = {p: p.read_text(encoding="utf-8", errors="ignore")
               for p in pkg_root.rglob("*.py")}

    # We configure a named logger, never the root one, so no basicConfig-style
    # call belongs anywhere in the package.
    for call in ("basicConfig", "dictConfig", "fileConfig"):
        assert [str(p) for p, src in sources.items() if call in src] == [], call

    # And only util/logs.py may attach a handler or set a level: a second site
    # is how a package starts double-logging or fighting itself over levels.
    for call in ("addHandler", "removeHandler", "setLevel"):
        hits = sorted(str(p) for p, src in sources.items() if call in src)
        assert hits == [str(Path(logs.__file__))], (call, hits)


# ─────────────────────────────────────────────────────────────────────────────
# Default settings: stderr output on a real (stubbed) pipeline run is
# byte-identical whether or not the logging region has run.
# ─────────────────────────────────────────────────────────────────────────────
def test_default_settings_leave_stderr_bytes_unchanged(stub_prompt, capsys, monkeypatch):
    monkeypatch.delenv("VVAHARNESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    from vvaharness.pipeline.stages import s3_decompose

    # "Before the change": nothing has ever configured logging, matching the
    # state this package was in prior to the logging-init region existing.
    _reset_channel()
    s3_decompose.run(make_taint_multi_ctx(), _decompose_cfg())
    before = capsys.readouterr().err
    assert before  # sanity: the "[s3] ast frontier" print really fired

    # "After the change", default settings: the region runs over a realistic
    # argv, finds no log flags, and passes argv through untouched.
    _reset_channel()
    argv = ["scan", "--repo", "/tmp/x", "--stop-after", "s9"]
    assert cli._configure_logging(list(argv)) == argv
    s3_decompose.run(make_taint_multi_ctx(), _decompose_cfg())
    after = capsys.readouterr().err

    assert after == before


def test_enabling_the_channel_does_not_double_a_line_root_already_shows(capsys, monkeypatch):
    """The reason we scope to the ``vvaharness`` logger with propagate=False:
    an embedding application that configured root must not see our lines twice."""
    monkeypatch.delenv("VVAHARNESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()
    # Stands in for the embedding application's own root handler; capsys has
    # already replaced sys.stderr, which StreamHandler() binds to by default.
    logging.root.handlers = [logging.StreamHandler()]
    logging.root.setLevel(logging.WARNING)

    assert logs.configure("warning") is True
    logging.getLogger("vvaharness.pipeline.stages.s3_decompose").warning("marker-not-doubled")

    err = capsys.readouterr().err
    assert err.count("marker-not-doubled") == 1


# ─────────────────────────────────────────────────────────────────────────────
# An INFO level makes a known structured log line visible.
# ─────────────────────────────────────────────────────────────────────────────
def test_info_level_surfaces_the_known_decompose_log_line(stub_prompt, capsys, monkeypatch):
    monkeypatch.setenv("VVAHARNESS_LOG_LEVEL", "INFO")
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    from vvaharness.pipeline.stages import s3_decompose

    _reset_channel()
    cli._configure_logging([])
    s3_decompose.run(make_taint_multi_ctx(), _decompose_cfg())
    err = capsys.readouterr().err

    assert "s3/decompose: starting task decomposition" in err


def test_default_level_does_not_surface_the_info_log_line(stub_prompt, capsys, monkeypatch):
    monkeypatch.delenv("VVAHARNESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    from vvaharness.pipeline.stages import s3_decompose

    _reset_channel()
    cli._configure_logging([])
    s3_decompose.run(make_taint_multi_ctx(), _decompose_cfg())
    err = capsys.readouterr().err

    assert "s3/decompose: starting task decomposition" not in err


# ─────────────────────────────────────────────────────────────────────────────
# --log-level / --log-file: parsed and stripped before any subcommand parser
# ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("flags", [
    ["--log-level", "debug"],
    ["--log-level=debug"],
])
def test_log_level_flag_is_stripped_from_argv_and_applied(monkeypatch, flags):
    monkeypatch.delenv("VVAHARNESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()

    rest = cli._configure_logging(["scan", *flags, "--repo", "/tmp/x"])

    # The three hand-rolled subcommand parsers would reject an unknown flag.
    assert rest == ["scan", "--repo", "/tmp/x"]
    assert logging.getLogger(_PKG_LOGGER).level == logging.DEBUG


def test_log_file_flag_sends_records_to_the_file_and_keeps_stderr_clean(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.delenv("VVAHARNESS_LOG_LEVEL", raising=False)
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()
    dest = tmp_path / "nested" / "run.log"

    rest = cli._configure_logging(
        ["scan", "--log-level", "info", "--log-file", str(dest), "--repo", "/tmp/x"])
    logging.getLogger("vvaharness.pipeline.stages.s3_decompose").info("marker-in-file")
    _close_our_handlers()

    assert rest == ["scan", "--repo", "/tmp/x"]
    assert "marker-in-file" in dest.read_text(encoding="utf-8")   # parent dir created for us
    assert "marker-in-file" not in capsys.readouterr().err


def test_flags_take_precedence_over_the_env_var(monkeypatch):
    monkeypatch.setenv("VVAHARNESS_LOG_LEVEL", "debug")
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()

    cli._configure_logging(["--log-level", "error"])

    assert logging.getLogger(_PKG_LOGGER).level == logging.ERROR


def test_reconfiguring_replaces_our_handler_instead_of_stacking(monkeypatch):
    # configure() is documented as idempotent; a second call (e.g. an
    # in-process main() invoked twice) must not double every line.
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()

    assert logs.configure("info") is True
    assert logs.configure("debug") is True

    assert len(_our_handlers()) == 1
    assert logging.getLogger(_PKG_LOGGER).level == logging.DEBUG


def test_records_are_redacted_before_they_reach_the_handler(capsys, monkeypatch):
    # The channel is a diagnostic surface, so a credential that reaches a log
    # call must not reach the log sink; that is why configure() installs a
    # redacting formatter rather than a plain one.
    monkeypatch.delenv("VVAHARNESS_LOG_FILE", raising=False)
    _reset_channel()

    assert logs.configure("info") is True
    logging.getLogger("vvaharness.util.test").info("key=%s", "AKIAIOSFODNN7EXAMPLE")

    err = capsys.readouterr().err
    assert "AKIAIOSFODNN7EXAMPLE" not in err
    assert "key=" in err
