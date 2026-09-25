"""Credentials handed to an MCP subprocess through a 0600 file (SEC-095 follow-up).

SEC-095 moved the API password and the bot token off argv and onto the spawn
config's ``env`` channel. That was enough for the pydantic-ai stdio client, but
not for the ACP bridge: ``claude-agent-acp`` hands the whole ``mcpServers``
config — ``env`` included — to the ``claude`` CLI as ``--mcp-config '<json>'``,
so every secret landed back on a command line readable by any local user
through ``ps``.

So the spawner no longer puts a secret in the spawn config at all. It writes the
values to a file only this OS user can read and passes the file's *path* in
``CONDOR_MCP_SECRETS_FILE``; the path is not a secret and may sit in ``ps``. The
subprocess calls :func:`load_secrets_file` first thing, before any settings are
parsed, and the values land in ``os.environ`` under the same names the spawner
used to inject — so every reader downstream (settings, routines that look up
``TELEGRAM_BOT_TOKEN``, their own children) is unchanged.

A leaf module, like ``_profiles.py``: it must not import a ``server.py``.
"""

from __future__ import annotations

import json
import logging
import os
import stat

log = logging.getLogger(__name__)

SECRETS_FILE_ENV = "CONDOR_MCP_SECRETS_FILE"

#: The only names a secrets file may set. The file is ours, but an allowlist
#: keeps it from ever becoming a way to set ``PATH`` or ``LD_PRELOAD`` in a
#: process that goes on to spawn others.
ALLOWED_SECRETS = frozenset(
    {
        "TELEGRAM_BOT_TOKEN",
        "HUMMINGBOT_API_USERNAME",
        "HUMMINGBOT_API_PASSWORD",
    }
)


def load_secrets_file() -> None:
    """Load the secrets file named by ``$CONDOR_MCP_SECRETS_FILE`` into the env.

    A no-op when the variable is unset (a standalone launch, e.g. from the
    checked-in ``.mcp.json``). A file that is a symlink, belongs to another user
    or is readable by group/other is refused rather than trusted: the process
    then starts without those credentials, which fails loudly at first use.
    """
    path = os.environ.get(SECRETS_FILE_ENV, "")
    if not path:
        return

    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        log.warning("Cannot open MCP secrets file %s: %s", path, exc)
        return

    with os.fdopen(fd, encoding="utf-8") as f:
        st = os.fstat(f.fileno())
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid():
            log.warning("Refusing MCP secrets file %s: not our regular file", path)
            return
        if st.st_mode & 0o077:
            log.warning(
                "Refusing MCP secrets file %s: mode %o is readable by others",
                path,
                stat.S_IMODE(st.st_mode),
            )
            return
        try:
            data = json.load(f)
        except ValueError as exc:
            log.warning("Unreadable MCP secrets file %s: %s", path, exc)
            return

    if not isinstance(data, dict):
        log.warning("Unreadable MCP secrets file %s: not a JSON object", path)
        return

    for name, value in data.items():
        if name in ALLOWED_SECRETS and isinstance(value, str) and value:
            os.environ[name] = value
