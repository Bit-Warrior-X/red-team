
# ============================================================
# core/tool_runner.py - Async subprocess wrapper
# ============================================================

import asyncio
import json
import logging
import shutil
from typing import Optional

log = logging.getLogger("redscanner.runner")


async def run_tool(
    cmd: list[str],
    timeout: int = 300,
    parse_json_lines: bool = False,
    stdin_input: Optional[str] = None,
    quiet: bool = False,
) -> dict:
    """
    Run an external CLI tool asynchronously.
    Returns {"stdout": str, "stderr": str, "returncode": int, "json_lines": list}
    """
    tool_name = cmd[0]
    if not shutil.which(tool_name):
        if not quiet:
            log.warning(f"Tool not found: {tool_name}. Skipping.")
        return {"stdout": "", "stderr": f"{tool_name} not installed", "returncode": -1, "json_lines": []}

    if not quiet:
        log.info(f"Running: {' '.join(cmd)}")
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if stdin_input is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdin_bytes = stdin_input.encode("utf-8") if stdin_input is not None else None
        stdout, stderr = await asyncio.wait_for(proc.communicate(stdin_bytes), timeout=timeout)
        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")

        json_lines = []
        if parse_json_lines:
            for line in stdout_str.strip().split("\n"):
                line = line.strip()
                if line:
                    try:
                        json_lines.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        return {
            "stdout": stdout_str,
            "stderr": stderr_str,
            "returncode": proc.returncode,
            "json_lines": json_lines,
        }
    except asyncio.TimeoutError:
        if not quiet:
            log.error(f"Tool timed out after {timeout}s: {tool_name}")
        stdout_str, stderr_str = "", "timeout"
        if proc is not None:
            try:
                proc.kill()
                out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
                stdout_str = out.decode("utf-8", errors="replace") if out else ""
                err_txt = err.decode("utf-8", errors="replace") if err else ""
                stderr_str = ("timeout\n" + err_txt).strip()
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        return {"stdout": stdout_str, "stderr": stderr_str, "returncode": -1, "json_lines": []}
    except Exception as e:
        if not quiet:
            log.error(f"Tool execution error: {e}")
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass
        return {"stdout": "", "stderr": str(e), "returncode": -1, "json_lines": []}
