"""Local CLI adapters with bounded lifetime and isolated working directories."""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import signal
import tempfile
from pathlib import Path
from typing import Any

from scripts.quorum_models import QuorumError, Review

MAX_OUTPUT = 250_000


async def bounded_process(
    args: list[str], prompt: str, cwd: Path, timeout: float, env: dict[str, str]
) -> str:
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            cwd=cwd,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        raise QuorumError("provider_unavailable") from None

    async def exchange() -> str:
        if process.stdin is None or process.stdout is None:
            raise QuorumError("provider_pipe_failed")
        process.stdin.write(prompt.encode())
        await process.stdin.drain()
        process.stdin.close()
        chunks = bytearray()
        while chunk := await process.stdout.read(8192):
            chunks.extend(chunk)
            if len(chunks) > MAX_OUTPUT:
                raise QuorumError("provider_output_too_large")
        if await process.wait() != 0:
            raise QuorumError("provider_nonzero_exit")
        return chunks.decode("utf-8")

    try:
        return await asyncio.wait_for(exchange(), timeout=timeout)
    except TimeoutError:
        raise QuorumError("provider_timeout") from None
    except (UnicodeError, BrokenPipeError, ConnectionResetError):
        raise QuorumError("provider_protocol_failed") from None
    finally:
        # The group includes descendants even if the original process has already exited.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        await process.wait()


def commands(provider: str, executable: str, folder: Path, *, web_tools: bool = True) -> list[str]:
    schema = json.dumps(Review.model_json_schema())
    if provider == "claude":
        return [
            executable,
            "-p",
            "--safe-mode",
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--no-session-persistence",
            "--permission-mode",
            "dontAsk",
            "--tools",
            "WebSearch,WebFetch" if web_tools else "",
            "--allowedTools",
            "WebSearch,WebFetch" if web_tools else "",
            "--output-format",
            "json",
            "--json-schema",
            schema,
        ]
    (folder / "schema.json").write_text(schema)
    return [
        executable,
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "-c",
        'approval_policy="never"',
        "-c",
        "features.shell_tool=false",
        "--output-schema",
        str(folder / "schema.json"),
        "--output-last-message",
        str(folder / "result.json"),
        "-",
    ]


async def invoke(provider: str, prompt: str, timeout: float, *, web_tools: bool = True) -> Review:
    if provider not in {"claude", "codex"}:
        raise QuorumError("unknown_provider")
    executable = shutil.which(provider)
    if executable is None:
        raise QuorumError("provider_not_installed")
    # Preserve CLI authentication, but never read credentials into prompts or artifacts.
    env = os.environ.copy()
    env.update(
        {
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "DISABLE_TELEMETRY": "1",
        }
    )
    with tempfile.TemporaryDirectory(prefix="quorum-provider-") as temporary:
        folder = Path(temporary)
        output = await bounded_process(
            commands(provider, executable, folder, web_tools=web_tools),
            prompt,
            folder,
            timeout,
            env,
        )
        if provider == "claude":
            try:
                envelope: Any = json.loads(output)
                if not isinstance(envelope, dict) or envelope.get("is_error"):
                    raise QuorumError("provider_nonzero_exit")
                return Review.model_validate(envelope.get("structured_output"))
            except (ValueError, TypeError):
                raise QuorumError("invalid_provider_result") from None
        result = folder / "result.json"
        if result.is_symlink() or not result.is_file() or result.stat().st_size > MAX_OUTPUT:
            raise QuorumError("missing_provider_result")
        try:
            return Review.model_validate_json(result.read_text())
        except (ValueError, OSError):
            raise QuorumError("invalid_provider_result") from None
