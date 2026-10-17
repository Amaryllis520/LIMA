"""Standalone resource sampling; no analysis, budgets, or runtime decisions."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psutil

COLLECTOR_ERROR = 125


def diagnose(diagnostics, scope, reason, pid=None):
    # Exception messages can contain argv or other secrets: persist categories only.
    item = {"scope": scope, "reason": reason}
    if pid is not None:
        item["pid"] = pid
    if item not in diagnostics:
        diagnostics.append(item)


class HostSampler:
    def __init__(self, root, diagnostics, root_exited=lambda: False):
        self.processes = {root.pid: root} if root is not None else {}
        self.root_pid = root.pid if root is not None else None
        self.root_exited = root_exited
        self.diagnostics = diagnostics
        self.result = {
            "sampled_peak_rss_bytes": None,
            "sample_count": 0,
            "measurement_source": "psutil process tree RSS sum",
            "complete": root is not None,
        }

    def sample(self):
        # Retain observed descendants even if their parent exits or they are reparented.
        for process in list(self.processes.values()):
            try:
                for child in process.children(recursive=True):
                    self.processes.setdefault(child.pid, child)
            except psutil.Error as exc:
                self._incomplete(process, exc)
        total, observed = 0, False
        for pid, process in list(self.processes.items()):
            try:
                total += process.memory_info().rss
                observed = True
            except psutil.Error as exc:
                self._incomplete(process, exc)
                if isinstance(exc, psutil.NoSuchProcess):
                    del self.processes[pid]
        if observed:
            self.result["sample_count"] += 1
            peak = self.result["sampled_peak_rss_bytes"]
            self.result["sampled_peak_rss_bytes"] = max(total, peak or 0)

    def _incomplete(self, process, exc):
        if (
            process.pid == self.root_pid
            and isinstance(exc, psutil.NoSuchProcess)
            and self.root_exited()
        ):
            return  # Confirmed normal root termination is not a lost child sample.
        self.result["complete"] = False
        diagnose(self.diagnostics, "host", type(exc).__name__, process.pid)


class WindowsJob:
    """Own descendants even after their parent exits; sets no resource limits."""

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ctypes = ctypes
        signatures = {
            "CreateJobObjectW": ([wintypes.LPVOID, wintypes.LPCWSTR], wintypes.HANDLE),
            "OpenProcess": ([wintypes.DWORD, wintypes.BOOL, wintypes.DWORD], wintypes.HANDLE),
            "AssignProcessToJobObject": ([wintypes.HANDLE, wintypes.HANDLE], wintypes.BOOL),
            "TerminateJobObject": ([wintypes.HANDLE, wintypes.UINT], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.api, name)
            function.argtypes, function.restype = arguments, result
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, pid):
        # PROCESS_SET_QUOTA | PROCESS_TERMINATE, required by AssignProcessToJobObject.
        process = self.api.OpenProcess(0x0100 | 0x0001, False, pid)
        if not process:
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        try:
            if not self.api.AssignProcessToJobObject(self.handle, process):
                raise self.ctypes.WinError(self.ctypes.get_last_error())
        finally:
            self.api.CloseHandle(process)

    def terminate(self):
        if not self.api.TerminateJobObject(self.handle, 130):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def close(self):
        # Normal completion must not kill commands deliberately left running by the parent.
        self.api.CloseHandle(self.handle)


def docker_json(executable, arguments):
    completed = subprocess.run(  # noqa: S603 - fixed read-only Docker argv, no shell.
        [executable, *arguments], shell=False, capture_output=True, text=True, timeout=2, check=True
    )
    return json.loads(completed.stdout)


def memory_bytes(value):
    match = re.fullmatch(r"\s*([0-9.]+)\s*([KMGTPE]?i?B)\s*", value)
    if not match:
        raise ValueError("invalid Docker memory unit")
    unit = match[2]
    exponent = "BKMGTPE".index(unit[0]) if unit != "B" else 0
    return int(float(match[1]) * (1024 if "i" in unit else 1000) ** exponent)


class ContainerSampler:
    """Only Docker inspect/stats, in a separate thread so host polling never waits on Docker."""

    def __init__(self, target, interval, diagnostics):
        self.result = None
        self.diagnostics = diagnostics
        self.target = target
        self.interval = interval
        self.stop = threading.Event()
        self.thread = None

    def start(self):
        executable = shutil.which("docker")
        if executable is None:
            diagnose(self.diagnostics, "container", "docker_unavailable")
            return
        self.thread = threading.Thread(target=self._run, args=(executable,), daemon=True)
        self.thread.start()

    def _run(self, executable):
        try:
            # Project only identity and limits: never request Config.Env or command fields.
            template = (
                '{"id":{{json .Id}},"image":{{json .Config.Image}},'
                '"image_id":{{json .Image}},"resource_limits":{'
                '"memory_bytes":{{json .HostConfig.Memory}},'
                '"memory_swap_bytes":{{json .HostConfig.MemorySwap}},'
                '"nano_cpus":{{json .HostConfig.NanoCpus}},'
                '"cpu_quota":{{json .HostConfig.CpuQuota}},'
                '"cpu_period":{{json .HostConfig.CpuPeriod}},'
                '"cpuset_cpus":{{json .HostConfig.CpusetCpus}}}}'
            )
            metadata = docker_json(
                executable,
                ["inspect", "--type", "container", "--format", template, "--", self.target],
            )
            while not self.stop.is_set():
                stats = docker_json(
                    executable,
                    ["stats", "--no-stream", "--format", "{{json .}}", "--", metadata["id"]],
                )
                if self.stop.is_set():
                    break  # Never mix measurements completed after command end into this run.
                memory = memory_bytes(stats["MemUsage"].split("/")[0])
                cpu = float(stats["CPUPerc"].rstrip("%"))
                if not math.isfinite(cpu) or cpu < 0:
                    raise ValueError("invalid CPU sample")
                if self.result is None:
                    self.result = {
                        **metadata,
                        "sampled_peak_memory_bytes": None,
                        "sampled_peak_cpu_percent": None,
                        "sample_count": 0,
                        "measurement_source": "docker CLI inspect + stats --no-stream",
                        "cpu_percent_sampling": "Docker stats CPU delta over its own "
                        "measurement window; may exceed 100% on multiple CPUs; "
                        "sampled maximum, not an exact CPU peak",
                        "memory_sampling": "Docker stats MemUsage (CLI rounded units; "
                        "Linux may subtract cache); not cgroup memory.peak",
                        "complete": True,
                    }
                self.result["sample_count"] += 1
                for key, value in (
                    ("sampled_peak_memory_bytes", memory),
                    ("sampled_peak_cpu_percent", cpu),
                ):
                    self.result[key] = max(self.result[key] or 0, value)
                if self.stop.wait(self.interval):
                    break
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as exc:
            diagnose(
                self.diagnostics,
                "container",
                "docker_unavailable_or_unreadable:" + type(exc).__name__,
            )
            if self.result is not None:
                self.result["complete"] = False

    def finish(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join()  # Each Docker subprocess has a 2 second timeout.
        if self.result is None:
            diagnose(self.diagnostics, "container", "no_sample_during_command")
        return self.result


def stop_tree(command, sampler, diagnostics, job=None):
    """Stop only this invocation's process group/tree plus already observed descendants."""
    root = sampler.processes.get(command.pid)
    if root is not None:
        try:
            for child in root.children(recursive=True):
                sampler.processes.setdefault(child.pid, child)
        except psutil.Error as exc:
            diagnose(diagnostics, "cleanup", type(exc).__name__)
    if os.name == "nt":
        if job is not None:
            try:
                job.terminate()
            except OSError as exc:
                diagnose(diagnostics, "cleanup", type(exc).__name__)
        # Windows has no POSIX process groups; /T also includes children between samples.
        if command.poll() is None:
            try:
                taskkill = str(
                    Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "taskkill.exe"
                )
                subprocess.run(  # noqa: S603 - OS tool, only the PID we started.
                    [taskkill, "/PID", str(command.pid), "/T", "/F"],
                    shell=False,
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError) as exc:
                diagnose(diagnostics, "cleanup", type(exc).__name__)
    else:
        try:
            os.killpg(command.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError as exc:
            diagnose(diagnostics, "cleanup", type(exc).__name__)
    processes = []
    for process in reversed(list(sampler.processes.values())):
        try:
            process.kill()
            processes.append(process)
        except psutil.NoSuchProcess:
            pass
        except psutil.Error as exc:
            diagnose(diagnostics, "cleanup", type(exc).__name__, process.pid)
    _, alive = psutil.wait_procs(processes, timeout=3)
    for process in alive:
        diagnose(diagnostics, "cleanup", "still_alive", process.pid)
    try:
        command.wait(timeout=3)
    except subprocess.TimeoutExpired:
        diagnose(diagnostics, "cleanup", "command_still_alive", command.pid)


class CollectorParser(argparse.ArgumentParser):
    def error(self, message):
        # Do not echo unrecognized arguments, which may include credentials.
        raise ValueError("invalid arguments; use --help")


def main(argv=None):
    parser = CollectorParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--interval-seconds", type=float, default=0.2)
    parser.add_argument("--container")
    temp_path = None
    command_exit_code = None
    try:
        arguments = list(sys.argv[1:] if argv is None else argv)
        if "--" not in arguments:
            if arguments == ["--help"]:
                parser.parse_args(arguments)
            raise ValueError("command must follow --")
        separator = arguments.index("--")
        options = parser.parse_args(arguments[:separator])
        command_argv = arguments[separator + 1 :]
        if (
            not command_argv
            or not math.isfinite(options.interval_seconds)
            or options.interval_seconds <= 0
        ):
            raise ValueError("command required and interval must be finite and positive")
        if os.path.lexists(options.output):
            raise FileExistsError("output exists")
        options.output.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(
            prefix=".performance-", suffix=".tmp", dir=options.output.parent
        )
        os.close(fd)
        temp_path = Path(temp_name)
        diagnostics = []
        data = {
            "schema_version": 1,
            "run_id": str(uuid.uuid4()),
            "started_at_utc": datetime.now(UTC).isoformat(),
            "wall_time_seconds": None,
            "command_exit_code": None,
            "sampling_interval_seconds": options.interval_seconds,
            "host": None,
            "container": None,
            "diagnostics": diagnostics,
            "partial": False,
        }
        container = (
            ContainerSampler(options.container, options.interval_seconds, diagnostics)
            if options.container
            else None
        )
        start = time.monotonic()
        command = None
        sampler = None
        job = None
        interrupted = False
        try:
            if os.name == "nt":
                job = WindowsJob()
            launch_interrupt = []
            previous_launch = signal.signal(signal.SIGINT, lambda *_: launch_interrupt.append(True))
            try:
                command = subprocess.Popen(  # noqa: S603 - explicit user argv; no shell.
                    command_argv,
                    shell=False,
                    **(
                        {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | 0x00000004}
                        if os.name == "nt"
                        else {"start_new_session": True}
                    ),
                )  # Windows CREATE_SUSPENDED: assign the job before any children can start.
                try:
                    root = psutil.Process(command.pid)
                except psutil.Error as exc:
                    root = None
                    diagnose(diagnostics, "host", type(exc).__name__, command.pid)
                sampler = HostSampler(
                    root, diagnostics, root_exited=lambda: command.poll() is not None
                )
                if job is not None:
                    job.assign(command.pid)
                    psutil.Process(command.pid).resume()
            finally:
                signal.signal(signal.SIGINT, previous_launch)
            if launch_interrupt:
                raise KeyboardInterrupt
            if container:
                container.start()
            while command.poll() is None:
                sampler.sample()
                try:
                    command.wait(timeout=options.interval_seconds)
                except subprocess.TimeoutExpired:
                    pass
        except KeyboardInterrupt:
            interrupted = True
            data["partial"] = True
            diagnose(diagnostics, "run", "interrupted")
        except Exception as exc:
            # Unexpected collector failures must also clean up an already started command.
            data["partial"] = True
            diagnose(diagnostics, "run", type(exc).__name__)
        finally:
            # Repeated Ctrl+C must not interrupt cleanup or atomic publication.
            previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
            try:
                if command is not None:
                    if data["partial"]:
                        if sampler is None:
                            sampler = HostSampler(None, diagnostics)
                        stop_tree(command, sampler, diagnostics, job)
                    command_exit_code = command.poll()
                if job is not None:
                    job.close()
                data["wall_time_seconds"] = time.monotonic() - start
                data["command_exit_code"] = command_exit_code
                data["host"] = (
                    sampler.result
                    if sampler
                    else {
                        "sampled_peak_rss_bytes": None,
                        "sample_count": 0,
                        "measurement_source": "psutil process tree RSS sum",
                        "complete": False,
                    }
                )
                if data["partial"] or not data["host"]["sample_count"]:
                    data["host"]["complete"] = False
                if not data["host"]["sample_count"]:
                    diagnose(diagnostics, "host", "no_sample_during_command")
                if container:
                    data["container"] = container.finish()
                with temp_path.open("w", encoding="utf-8") as stream:
                    json.dump(data, stream, ensure_ascii=False, indent=2, allow_nan=False)
                    stream.write("\n")
                    stream.flush()
                    os.fsync(stream.fileno())
                # Hard-link publication is atomic AND fails if the target exists on both OSes.
                # No unsafe replace/rename fallback on filesystems without hard links.
                os.link(temp_path, options.output)
            finally:
                signal.signal(signal.SIGINT, previous)
        if interrupted:
            return 130
        if data["partial"]:
            print(
                f"collector_error: run incomplete; command_exit_code={command_exit_code}",
                file=sys.stderr,
            )
            return COLLECTOR_ERROR
        return command_exit_code
    except (OSError, ValueError) as exc:
        print(
            f"collector_error: {type(exc).__name__}; command_exit_code={command_exit_code}",
            file=sys.stderr,
        )
        return COLLECTOR_ERROR
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError as exc:
                print(
                    f"collector_error: temp cleanup {type(exc).__name__}; "
                    f"command_exit_code={command_exit_code}",
                    file=sys.stderr,
                )
                return COLLECTOR_ERROR
