"""PraiseAssistant command-line interface.

JSON on stdout for success; a JSON ``{"error": ...}`` object on stderr with a
nonzero exit code for every failure (fail closed). All subcommands use the same
handlers as the resident, engagement-bound JSONL transport. No per-message
interpreter startup and no shell execution.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import policy, runtime
from .runtime import PraiseError



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
    if args.agent:
        if not isinstance(finding, dict):
            raise PraiseError("candidate input must be a JSON object")
        finding["producer_agent"] = args.agent
    return runtime.create_candidate(_engagement_dir(args), finding)


def _cmd_show(args):
    return runtime.show(_engagement_dir(args), args.candidate, compact=args.compact)


def _cmd_gate(args):
    return runtime.gate_candidate(
        _engagement_dir(args), args.candidate, args.decision, args.reason, args.model, args.agent
    )


def _cmd_reproduce(args):
    return runtime.add_reproduction(
        _engagement_dir(args), args.candidate, args.run_id, args.clean_state, args.evidence, args.model, args.agent
    )


def _cmd_verdict(args):
    return runtime.record_verdict(
        _engagement_dir(args), args.candidate, args.decision, args.reason, args.model, args.evidence, args.agent
    )


def _cmd_dispatch(args):
    return runtime.dispatch(
        _engagement_dir(args), args.stage, args.candidate, args.escalated, args.reason,
        tier=args.tier, packet=args.packet, attempt=args.attempt,
    )


def _cmd_packet(args):
    try:
        with open(args.input, "rb") as fh:
            raw = fh.read(8193)
        if len(raw) > 8192:
            raise PraiseError("evidence packet exceeds 8192 UTF-8 bytes")
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise PraiseError(f"cannot read evidence packet input: {exc}") from exc
    return runtime.create_packet(_engagement_dir(args), data, args.model, args.agent)


def _cmd_review(args):
    return runtime.record_review(
        _engagement_dir(args), args.candidate, args.decision, args.reason, args.model, args.evidence, args.agent,
    )


def _cmd_lead(args):
    passthrough = args.native_args
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]
    for arg in passthrough:
        key = arg.split("=", 1)[0]
        if key in ("--model", "--provider", "--cwd", "--thinking") or key.startswith("--thinking-") or (
            arg.startswith("-") and not arg.startswith("--") and len(arg) > 1 and arg[1] in "mpc"
        ):
            raise PraiseError("lead passthrough cannot override model, provider, cwd, or thinking")
    argv = runtime.lead_launch(_engagement_dir(args), args.recover) + passthrough
    try:
        os.execvp(argv[0], argv)
    except OSError as exc:
        raise PraiseError(f"native lead launcher failed: {exc}") from exc


def _cmd_register(args):
    return runtime.register_agent(
        _engagement_dir(args), args.session, args.name, args.role, args.model, args.candidate,
    )


def _cmd_message(args):
    return runtime.send_message(
        _engagement_dir(args), args.sender, args.model, args.to, args.kind, json.loads(args.data),
        args.candidate, args.reply_to, args.evidence, args.key,
    )


def _cmd_inbox(args):
    return runtime.inbox(_engagement_dir(args), args.agent, args.after, args.limit)


def _cmd_peers(args):
    return runtime.peers(_engagement_dir(args), args.candidate)


def _cmd_scope(args):
    return runtime.load_scope(_engagement_dir(args))


def _cmd_project(args):
    return runtime.project_messages(_engagement_dir(args))


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
    return runtime.validate_fix(_engagement_dir(args), args.candidate, args.model, gates, args.agent)


# --- parser ----------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(
        prog="praise",
        description="Cross-agent role and communication control: JSON messages, registration, "
        "inboxes, and engagement-scoped state.",
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


    p = sub.add_parser("lead", help="Operator-only configured Lead launcher; no provider fallback")
    p.add_argument("--recover", type=int, help="Explicit durable configured Lead execution-failure close sequence")
    p.add_argument("native_args", nargs=argparse.REMAINDER, help="Native omp flags after --")
    p.set_defaults(func=_cmd_lead)

    p = sub.add_parser("scope", help="Read scope without case or chat history")
    p.set_defaults(func=_cmd_scope)

    p = sub.add_parser("register", help="Bind a session to a short engagement-local agent id")
    p.add_argument("--session", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--role", required=True, choices=["lead", "planner", "scout", "finder", "verifier", "exploiter", "skeptic", "reviewer", "tester"])
    p.add_argument("--model", required=True)
    p.add_argument("--candidate")
    p.set_defaults(func=_cmd_register)

    p = sub.add_parser("message", help="Send a scoped JSON message")
    p.add_argument("--from", dest="sender", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--kind", required=True, choices=["ask", "reply", "close"])
    p.add_argument("--data", required=True, help="JSON object; at most 2048 UTF-8 bytes")
    p.add_argument("--candidate")
    p.add_argument("--reply-to", type=int)
    p.add_argument("--evidence", action="append", default=[])
    p.add_argument("--key", help="Idempotency key; changed content fails closed")
    p.set_defaults(func=_cmd_message)

    p = sub.add_parser("inbox", help="Read addressed messages after a durable sequence")
    p.add_argument("--agent", required=True)
    p.add_argument("--after", type=int, default=0)
    p.add_argument("--limit", type=int, default=32)
    p.set_defaults(func=_cmd_inbox)

    p = sub.add_parser("peers", help="Read a bounded scoped agent roster")
    p.add_argument("--candidate")
    p.set_defaults(func=_cmd_peers)

    p = sub.add_parser("project", help="Recover the append-only audit projection")
    p.set_defaults(func=_cmd_project)

    sub.add_parser("serve", help="Bound resident JSONL transport; no network listener")

    return parser




# --- entrypoint ------------------------------------------------------------


MAX_RPC_BYTES = 1024 * 1024


def _execute(args):
    func = getattr(args, "func", None)
    if func is None:
        raise PraiseError("no command specified")
    return func(args)


def _serve(directory: str, parser: argparse.ArgumentParser) -> int:
    runtime.load_scope(directory)
    while True:
        line = sys.stdin.buffer.readline(MAX_RPC_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_RPC_BYTES or not line.endswith(b"\n"):
            _emit_error(PraiseError("resident request exceeds the JSONL frame limit"))
            return 1
        request_id = None
        result = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or type(request.get("id")) is not int:
                raise PraiseError("resident request requires an integer id")
            request_id = request["id"]
            argv = request.get("args")
            if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
                raise PraiseError("resident request requires command arguments")
            if argv[0] in ("init", "serve", "lead") or any(
                a in ("--engagement", "--help", "-h") or a.startswith("--engagement=") for a in argv
            ):
                raise PraiseError("resident transport is bound to one engagement")
            args = parser.parse_args(["--engagement", directory, *argv])
            result = _execute(args)
            response = {"id": request_id, "ok": True, "data": result}
            encoded = runtime._json(response)
            if len(encoded.encode("utf-8")) > MAX_RPC_BYTES:
                raise PraiseError("resident response exceeds the JSONL frame limit; request compact data")
        except Exception as exc:  # no command retry: a mutation may already have committed
            error = str(exc) if isinstance(exc, (PraiseError, json.JSONDecodeError)) else f"{type(exc).__name__}: {exc}"
            encoded = runtime._json({"id": request_id, "ok": False, "error": error})
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()
        if isinstance(result, dict) and result.get("_messages"):
            try:
                runtime.project_messages(directory)
            except Exception as exc:
                sys.stderr.write(f"Committed messages need audit recovery: {type(exc).__name__}\n")
                sys.stderr.flush()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except PraiseError as exc:
        _emit_error(exc)
        return 2
    try:
        if args.command == "serve":
            return _serve(_engagement_dir(args), parser)
        result = _execute(args)
    except (PraiseError, json.JSONDecodeError) as exc:
        _emit_error(exc)
        return 1
    except json.JSONDecodeError as exc:
        _emit_error(PraiseError(f"invalid JSON: {exc}"))
        return 1
    except Exception as exc:
        _emit_error(PraiseError(f"{type(exc).__name__}: {exc}"))
        return 1
    if result is None:
        return 0
    sys.stdout.write(runtime._json(result) + "\n")
    sys.stdout.flush()
    if result.get("_messages"):
        try:
            runtime.project_messages(_engagement_dir(args))
        except Exception as exc:
            sys.stderr.write(f"Committed messages need audit recovery: {type(exc).__name__}\n")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
