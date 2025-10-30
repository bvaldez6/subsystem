# backend/tools/runner.py
import subprocess, shlex, logging, tempfile, os, json
log = logging.getLogger("runner")

# Map logical tool names -> docker image to run
TOOL_IMAGE = {
    "gobuster": "bvaldez/gobuster:latest",    # change to your image
    # add more tools: "nmap": "instrumented/nmap:latest", ...
}

def sanitize_args(args):
    # basic sanitizer: only allow primitive types
    safe = {}
    for k, v in (args or {}).items():
        if isinstance(v, (str,int,float,bool)):
            safe[k] = v
    return safe

def run_tool_in_docker(tool, subcommand, args, target, timeout=300):
    """
    Runs a tool inside docker and returns (exit_code, stdout, stderr).
    This function MUST be customized to the exact container/image and CLI semantics.
    """
    if tool not in TOOL_IMAGE:
        raise ValueError("tool not available")

    img = TOOL_IMAGE[tool]
    args = sanitize_args(args)
    # Example for gobuster dir mode
    if tool == "gobuster" and subcommand == "dir":
        wordlist = args.get("w")
        threads = int(args.get("t", 10))
        if not wordlist:
            raise ValueError("missing required arg 'w' (wordlist path inside image)")

        # Build docker command. Use --network none or a controlled network in production.
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            img,
            "gobuster", "dir",
            "-u", target,
            "-w", wordlist,
            "-t", str(threads)
        ]
    else:
        raise ValueError("tool/subcommand not implemented")

    log.info("Running tool container: %s", " ".join(shlex.quote(p) for p in cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        return 124, e.stdout or "", f"Timeout after {timeout}s"
    except Exception as e:
        return 255, "", str(e)

