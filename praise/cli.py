"""Praise role configuration, native OMP launch, and bounded JSON coordination."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import config, installation, policy, runtime
from .errors import PraiseError

MAX_RPC_BYTES = 1024 * 1024
RESIDENT_COMMANDS = frozenset(("scope", "register", "message", "inbox", "peers", "project", "show", "dispatch"))


class _ArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise PraiseError(f"argument error: {message}")


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)


def _engagement_dir(args) -> str:
    return str(Path(args.engagement or os.environ.get("PRAISE_ENGAGEMENT") or os.getcwd()).expanduser().resolve())


def _cmd_install(args):
    return installation.install(args.home, overwrite=args.overwrite, dry_run=args.dry_run, restore_backup=args.restore_backup)


def _cmd_set_agent(args):
    return config.set_role_model(args.role, args.model)


def _model_description(selector):
    provider, _, name = selector.partition("/")
    model, _, effort = name.partition(":")
    return {"provider": provider, "name": model, "effort": effort or None}


def _render_table(header, rows):
    widths = [max(len(header[index]), *(len(row[index]) for row in rows)) for index in range(len(header))]
    return ["  ".join(row[index].ljust(widths[index]) for index in range(len(header))).rstrip() for row in (header, *rows)]


def _format_agents(display, directory):
    changed = sum(1 for entry in display["roles"] if entry["model"] != entry["default_model"])
    lines = [f"Roles ({len(display['roles'])} configured, {changed} changed from the packaged defaults)",
             "", *["  " + line for line in _render_table(
                 ["ROLE", "PROVIDER", "MODEL", "EFFORT", "SPECIALIZATION"],
                 [[entry["role"], entry["model_description"]["provider"], entry["model_description"]["name"],
                   entry["model_description"]["effort"] or "-",
                   entry["description"] + (f" (packaged default: {entry['default_model']})"
                                            if entry["model"] != entry["default_model"] else "")]
                  for entry in display["roles"]])]]
    if directory is None:
        return "\n".join(lines) + "\n"
    agents = display["participants"]["agents"]
    lines += ["", f"Participants ({len(agents)} registered in {directory})"]
    if not agents:
        return "\n".join([*lines, "  none registered"]) + "\n"
    lines += ["", *["  " + line for line in _render_table(
        ["ID", "NAME", "ROLE", "MODEL", "PROVENANCE", "PARENT"],
        [[entry["id"], entry["name"], entry["role"], entry["model"], entry["model_source"], entry.get("parent") or "-"]
         for entry in agents])],
        "", "  host = model observed from the running agent; asserted = selector supplied at registration."]
    if display["participants"]["more"]:
        lines.append("  Showing the 32 most recent participants.")
    return "\n".join(lines) + "\n"


def _cmd_get_agents(args):
    catalog = config.load_roles()
    defaults = config.default_roles()["models"]
    result = {"schema_version": config.CONFIG_SCHEMA_VERSION, "roles": [
        {"role": role, "model": catalog["models"][role], "model_description": _model_description(catalog["models"][role]),
         "default_model": defaults[role], "description": config.ROLE_DESCRIPTIONS[role]}
        for role in config.ROLE_NAMES
    ]}
    directory = None
    # A configured selector is not a participant's observed host model.
    if args.engagement is not None:
        directory = _engagement_dir(args)
        runtime.load_scope(directory)
        result["participants"] = runtime.peers(directory)
    if args.json:
        return result
    sys.stdout.write(_format_agents(result, directory))
    sys.stdout.flush()
    return None


def _cmd_start_lead_agent(args):
    directory = str(Path(args.directory).expanduser().resolve())
    passthrough = list(args.native_args)
    if passthrough and passthrough[0] == "--":
        passthrough = passthrough[1:]
    extension = config.agent_dir() / "extensions/praise-router.js"
    if not extension.is_file():
        raise PraiseError("installed Praise extension not found; run praise install first")
    if (Path(directory) / "scope.json").exists():
        runtime.load_scope(directory)
    else:
        if not args.program or not args.basis or not args.asset:
            raise PraiseError("new engagements require --program, --basis, and --asset")
        runtime.init_engagement(directory, program=args.program, basis=args.basis, assets=args.asset,
                                mode=args.mode or "source", methods=args.method, max_requests=args.max_requests,
                                interval_seconds=args.interval)
    argv = ["omp", "--cwd", directory, "-e", str(extension), *passthrough]
    try:
        os.execvp(argv[0], argv)
    except OSError as exc:
        raise PraiseError(f"native main launcher failed: {exc}") from exc


def _cmd_dispatch(args):
    runtime.load_scope(_engagement_dir(args))
    return config.dispatch(args.role)


def _cmd_scope(args):
    return runtime.load_scope(_engagement_dir(args))


def _cmd_register(args):
    return runtime.register_agent(_engagement_dir(args), args.session, args.name, args.role, args.model,
                                  parent=args.parent, observed=args.observed)


def _cmd_message(args):
    if len(args.data.encode("utf-8")) > 2048:
        raise PraiseError("message data exceeds 2048 UTF-8 bytes")
    return runtime.send_message(_engagement_dir(args), args.sender, args.model, args.to, args.kind,
                                json.loads(args.data), reply_to=args.reply_to, evidence=args.evidence, key=args.key)


def _cmd_inbox(args):
    return runtime.inbox(_engagement_dir(args), args.agent, args.after, args.limit)


def _cmd_peers(args):
    return runtime.peers(_engagement_dir(args))


def _cmd_project(args):
    return runtime.project_messages(_engagement_dir(args))


def _cmd_show(args):
    return runtime.show(_engagement_dir(args))


def _build_parser():
    parser = _ArgumentParser(prog="praise", description=__doc__)
    parser.add_argument("--engagement", help="Explicit engagement directory for coordination")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install", help="Install packaged OMP integration with backups")
    p.add_argument("--home", type=Path, help="Install into HOME/.omp/agent instead of the selected OMP profile")
    p.add_argument("--overwrite", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--restore-backup", type=Path)
    p.set_defaults(func=_cmd_install)
    p = sub.add_parser("setAgent", help="Configure one canonical role's model selector")
    p.add_argument("--role", choices=config.ROLE_NAMES, required=True)
    p.add_argument("--model", required=True)
    p.set_defaults(func=_cmd_set_agent)
    p = sub.add_parser("getAgents", help="List configured roles; participants only with --engagement")
    # Permit the public documented form `getAgents --engagement DIR` as well.
    p.add_argument("--engagement", default=argparse.SUPPRESS)
    p.add_argument("--json", action="store_true", help="Emit the machine-readable schema instead of the tables")
    p.set_defaults(func=_cmd_get_agents)
    p = sub.add_parser("startLeadAgent", help="Initialize or resume an engagement and start the main session on the terminal-selected model")
    p.add_argument("--directory", required=True)
    p.add_argument("--program")
    p.add_argument("--basis")
    p.add_argument("--asset", action="append")
    p.add_argument("--mode", choices=policy.ALLOWED_MODES)
    p.add_argument("--method", action="append")
    p.add_argument("--max-requests", type=int, default=0)
    p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("native_args", nargs=argparse.REMAINDER, help="Native OMP arguments after --")
    p.set_defaults(func=_cmd_start_lead_agent)
    p = sub.add_parser("scope")
    p.set_defaults(func=_cmd_scope)
    p = sub.add_parser("register")
    p.add_argument("--session", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--role", choices=(*config.ROLE_NAMES, config.MAIN_ROLE), required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--parent")
    p.add_argument("--observed", action="store_true")
    p.set_defaults(func=_cmd_register)
    p = sub.add_parser("message")
    p.add_argument("--sender", required=True)
    p.add_argument("--model", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--kind", choices=("ask", "reply", "close"), required=True)
    p.add_argument("--data", required=True)
    p.add_argument("--reply-to", type=int)
    p.add_argument("--evidence", action="append", default=[])
    p.add_argument("--key")
    p.set_defaults(func=_cmd_message)
    p = sub.add_parser("inbox")
    p.add_argument("--agent", required=True)
    p.add_argument("--after", type=int, default=0)
    p.add_argument("--limit", type=int, default=32)
    p.set_defaults(func=_cmd_inbox)
    p = sub.add_parser("peers")
    p.set_defaults(func=_cmd_peers)
    p = sub.add_parser("project")
    p.set_defaults(func=_cmd_project)
    p = sub.add_parser("show")
    p.set_defaults(func=_cmd_show)
    p = sub.add_parser("dispatch")
    p.add_argument("--role", choices=config.ROLE_NAMES, required=True)
    p.set_defaults(func=_cmd_dispatch)
    sub.add_parser("serve", help="Engagement-bound resident JSONL coordination transport")
    return parser


def _execute(args):
    return args.func(args)


def _emit_error(exc):
    sys.stderr.write(_json({"error": str(exc)}) + "\n")


def _project_committed(directory, result):
    if isinstance(result, dict) and result.get("_messages"):
        try:
            runtime.project_messages(directory)
        except Exception as exc:
            sys.stderr.write(f"Committed messages need audit recovery: {type(exc).__name__}\n")
            sys.stderr.flush()


def _serve(directory, parser):
    runtime.load_scope(directory)
    while True:
        line = sys.stdin.buffer.readline(MAX_RPC_BYTES + 1)
        if not line:
            return 0
        if len(line) > MAX_RPC_BYTES or not line.endswith(b"\n"):
            _emit_error(PraiseError("resident request exceeds the JSONL frame limit"))
            return 1
        request_id, result = None, None
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or type(request.get("id")) is not int:
                raise PraiseError("resident request requires an integer id")
            request_id = request["id"]
            argv = request.get("args")
            if not isinstance(argv, list) or not argv or not all(isinstance(arg, str) for arg in argv):
                raise PraiseError("resident request requires command arguments")
            if argv[0] not in RESIDENT_COMMANDS or any(arg in ("--engagement", "--help", "-h") or arg.startswith("--engagement=") for arg in argv):
                raise PraiseError("resident transport allows internal coordination commands only and is bound to one engagement")
            result = _execute(parser.parse_args(["--engagement", directory, *argv]))
            encoded = _json({"id": request_id, "ok": True, "data": result})
            if len(encoded.encode("utf-8")) > MAX_RPC_BYTES:
                raise PraiseError("resident response exceeds the JSONL frame limit")
        except Exception as exc:
            # Never replay: the operation may already have committed.
            encoded = _json({"id": request_id, "ok": False, "error": str(exc)})
        sys.stdout.write(encoded + "\n")
        sys.stdout.flush()
        _project_committed(directory, result)


def main(argv=None) -> int:
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
        if result is not None:
            sys.stdout.write(_json(result) + "\n")
            sys.stdout.flush()
            _project_committed(_engagement_dir(args), result)
        return 0
    except Exception as exc:
        _emit_error(exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
