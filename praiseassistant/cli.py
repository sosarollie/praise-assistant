"""PraiseAssistant command-line interface.

JSON on stdout for success; a JSON ``{"error": ...}`` object on stderr with a
nonzero exit code for every failure (fail closed). The ``learn`` command tree is
delegated to ``praiseassistant.learning`` via a deferred import so the learning
slice can be completed independently.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import policy, runtime
from .runtime import PraiseError
from . import learning


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str):  # noqa: D401 - argparse hook
        raise PraiseError(f"argument error: {message}")




def _engagement_dir(args) -> str:
    explicit = getattr(args, "engagement", None)
    if explicit:
        return os.path.abspath(explicit)
    env = os.environ.get("PRAISEASSISTANT_ENGAGEMENT")
    if env:
        return os.path.abspath(env)
    return os.path.abspath(os.getcwd())


def _emit_error(exc: Exception) -> None:
    sys.stderr.write(json.dumps({"error": str(exc)}, sort_keys=True) + "\n")


# --- command handlers ------------------------------------------------------


def _cmd_init(args):
    return runtime.init_engagement(
        args.directory,
        program=args.program,
        basis=args.basis,
        assets=args.asset,
        mode=args.mode,
        methods=args.method,
        max_requests=args.max_requests,
        interval_seconds=args.interval,
    )


def _cmd_candidate(args):
    finding = runtime.read_json_input(args.input)
    return runtime.create_candidate(_engagement_dir(args), finding)


def _cmd_show(args):
    return runtime.show(_engagement_dir(args), getattr(args, "candidate", None))


def _cmd_gate(args):
    return runtime.gate_candidate(
        _engagement_dir(args), args.candidate, args.decision, args.reason, args.model
    )


def _cmd_reproduce(args):
    return runtime.add_reproduction(
        _engagement_dir(args), args.candidate, args.run_id, args.clean_state, args.evidence, args.model
    )


def _cmd_verdict(args):
    return runtime.record_verdict(
        _engagement_dir(args), args.candidate, args.decision, args.reason, args.model, args.evidence
    )


def _cmd_dispatch(args):
    return runtime.dispatch(
        _engagement_dir(args), args.stage, args.candidate, args.escalated, args.reason
    )


def _cmd_chat(args):
    return runtime.record_event(
        _engagement_dir(args), args.role, args.model, args.summary, args.ask, args.close, args.evidence
    )


def _cmd_request(args):
    headers = None
    if args.headers_file:
        headers = runtime.read_json_input(args.headers_file)
    elif args.headers_json:
        try:
            headers = json.loads(args.headers_json)
        except json.JSONDecodeError as exc:
            raise PraiseError(f"invalid --headers-json: {exc}") from exc
    return runtime.perform_request(
        _engagement_dir(args),
        args.url,
        args.method,
        args.role,
        args.model,
        args.candidate,
        args.clean_state,
        headers,
        args.body,
    )


def _cmd_validate_fix(args):
    gates = runtime.read_json_input(args.input)
    return runtime.validate_fix(_engagement_dir(args), args.candidate, args.model, gates)


# --- parser ----------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="praiseassistant",
        description="Evidence-based pentest workflow control: candidates, reproductions, "
        "verdicts, dispatch, chat, controlled requests, and reviewed learning.",
    )
    parser.add_argument(
        "--engagement",
        dest="engagement",
        default=None,
        help="Engagement directory (default: $PRAISEASSISTANT_ENGAGEMENT or the current directory)",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    p = sub.add_parser("init", help="Initialize an engagement directory")
    p.add_argument("--directory", required=True, help="Absolute engagement directory to create")
    p.add_argument("--program", required=True, help="Program name")
    p.add_argument("--basis", required=True, help="Authorization basis")
    p.add_argument("--asset", action="append", required=True, help="Allowed asset (repeatable)")
    p.add_argument("--mode", choices=list(policy.ALLOWED_MODES), default="source")
    p.add_argument("--max-requests", type=int, default=0, help="Request budget (default 0)")
    p.add_argument("--interval", type=float, default=1.0, help="Throttle seconds (default 1.0)")
    p.add_argument("--method", action="append", help="Allowed method (repeatable; default GET)")
    p.set_defaults(func=_cmd_init)

    p = sub.add_parser("candidate", help="Create a candidate from a normalized finding JSON file")
    p.add_argument("--input", required=True, help="Finding JSON file")
    p.set_defaults(func=_cmd_candidate)

    p = sub.add_parser("show", help="Show engagement state or a single candidate")
    p.add_argument("--candidate", help="Candidate id")
    p.set_defaults(func=_cmd_show)

    p = sub.add_parser("gate", help="Apply a gate decision")
    p.add_argument("--candidate", required=True)
    p.add_argument("--decision", required=True, choices=list(runtime.GATE_DECISIONS))
    p.add_argument("--reason", required=True)
    p.add_argument("--model", required=True, help="Observed model identifier")
    p.set_defaults(func=_cmd_gate)

    p = sub.add_parser("reproduce", help="Record one clean-state reproduction")
    p.add_argument("--candidate", required=True)
    p.add_argument("--run-id", required=True, dest="run_id")
    p.add_argument("--clean-state", required=True, dest="clean_state")
    p.add_argument("--evidence", required=True, help="Evidence reference")
    p.add_argument("--model", required=True, help="Observed model identifier")
    p.set_defaults(func=_cmd_reproduce)

    p = sub.add_parser("verdict", help="Record a verdict")
    p.add_argument("--candidate", required=True)
    p.add_argument("--decision", required=True, choices=list(runtime.VERDICT_DECISIONS))
    p.add_argument("--reason", required=True)
    p.add_argument("--model", required=True, help="Observed model identifier")
    p.add_argument("--evidence", action="append", default=[], help="Evidence reference (repeatable)")
    p.set_defaults(func=_cmd_verdict)

    p = sub.add_parser("dispatch", help="Resolve a stage to an agent and model")
    p.add_argument("--stage", required=True, choices=list(runtime.STAGES))
    p.add_argument("--candidate", help="Candidate id (required for proof/verdict/patch)")
    p.add_argument("--escalated", action="store_true")
    p.add_argument("--reason", help="Escalation reason")
    p.set_defaults(func=_cmd_dispatch)

    p = sub.add_parser("chat", help="Record a serialized chat entry")
    p.add_argument("--role", required=True)
    p.add_argument("--model", required=True, help="Observed model identifier")
    p.add_argument("--summary", required=True)
    p.add_argument("--ask", help="Question/request for another role")
    p.add_argument("--close", help="Closing statement/decision")
    p.add_argument("--evidence", action="append", default=[], help="Evidence reference (repeatable)")
    p.set_defaults(func=_cmd_chat)

    p = sub.add_parser("request", help="Perform one controlled, in-scope HTTP request")
    p.add_argument("--url", required=True)
    p.add_argument("--method", default="GET")
    p.add_argument("--role", required=True)
    p.add_argument("--model", required=True, help="Observed model identifier")
    p.add_argument("--candidate", help="Candidate id")
    p.add_argument("--clean-state", dest="clean_state", help="Clean-state id")
    header_input = p.add_mutually_exclusive_group()
    header_input.add_argument("--headers-json", help="Request headers as a JSON object")
    header_input.add_argument("--headers-file", help="Provided request headers JSON file; keeps values out of argv")
    p.add_argument("--body", help="Request body text")
    p.set_defaults(func=_cmd_request)

    p = sub.add_parser("validate-fix", help="Validate a proposed fix against four gates")
    p.add_argument("--candidate", required=True)
    p.add_argument("--model", required=True, help="Observed model identifier")
    p.add_argument("--input", required=True, help="Fix-validation JSON file")
    p.set_defaults(func=_cmd_validate_fix)

    learning.configure_parser(sub)

    return parser




# --- entrypoint ------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except PraiseError as exc:
        _emit_error(exc)
        return 2

    if getattr(args, "command", None) == "learn":
        return learning.run(args)

    func = getattr(args, "func", None)
    if func is None:
        _emit_error(PraiseError("no command specified"))
        return 2

    try:
        result = func(args)
    except PraiseError as exc:
        _emit_error(exc)
        return 1
    except json.JSONDecodeError as exc:
        _emit_error(PraiseError(f"invalid JSON: {exc}"))
        return 1
    except Exception as exc:  # noqa: BLE001 - fail closed without leaking internals
        _emit_error(PraiseError(f"{type(exc).__name__}: {exc}"))
        return 1

    if result is None:
        return 0
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
