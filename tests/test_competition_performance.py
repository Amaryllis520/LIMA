"""Offline contracts for the competition resource collector."""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import psutil

from lima import competition_performance as perf


class CompetitionPerformanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.output = Path(self.tmp.name) / "performance.json"

    def run_local(self, code, *options):
        return perf.main(
            [
                "--output",
                str(self.output),
                "--interval-seconds",
                "0.02",
                *options,
                "--",
                sys.executable,
                "-c",
                code,
            ]
        )

    def read(self):
        return json.loads(self.output.read_text(encoding="utf-8"))

    def test_success_and_schema_and_privacy(self):
        self.assertEqual(self.run_local("import time; secret='credential'; time.sleep(.1)"), 0)
        data = self.read()
        for key in (
            "schema_version",
            "run_id",
            "started_at_utc",
            "wall_time_seconds",
            "command_exit_code",
            "sampling_interval_seconds",
            "host",
            "container",
            "diagnostics",
            "partial",
        ):
            self.assertIn(key, data)
        self.assertGreater(data["wall_time_seconds"], 0)
        self.assertGreater(data["host"]["sample_count"], 0)
        self.assertGreater(data["host"]["sampled_peak_rss_bytes"], 0)
        self.assertIn("psutil", data["host"]["measurement_source"])
        self.assertIsNone(data["container"])
        self.assertNotIn("credential", self.output.read_text())
        self.assertNotIn("environ", self.output.read_text())

    def test_failed_command_preserves_exit(self):
        self.assertEqual(self.run_local("raise SystemExit(7)"), 7)
        self.assertEqual(self.read()["command_exit_code"], 7)

    def test_no_docker_does_not_change_command_exit(self):
        with patch.object(perf.shutil, "which", return_value=None):
            self.assertEqual(self.run_local("raise SystemExit(9)", "--container", "sidecar"), 9)
        self.assertIsNone(self.read()["container"])
        self.assertIn("docker_unavailable", str(self.read()["diagnostics"]))

    def test_existing_output_refused_before_launch(self):
        self.output.write_text("keep", encoding="utf-8")
        with patch.object(perf.subprocess, "Popen") as launch:
            self.assertEqual(self.run_local("pass"), perf.COLLECTOR_ERROR)
        launch.assert_not_called()
        self.assertEqual(self.output.read_text(), "keep")

    def test_invalid_configuration_refused(self):
        for interval in ("0", "-1", "nan", "inf"):
            with self.subTest(interval=interval), patch.object(perf.subprocess, "Popen") as launch:
                self.assertEqual(
                    perf.main(
                        [
                            "--output",
                            str(self.output),
                            "--interval-seconds",
                            interval,
                            "--",
                            sys.executable,
                            "-c",
                            "pass",
                        ]
                    ),
                    perf.COLLECTOR_ERROR,
                )
                launch.assert_not_called()

    def test_permission_failure_is_not_zero(self):
        root = Mock(pid=123)
        root.children.return_value = []
        root.memory_info.side_effect = psutil.AccessDenied(123)
        diagnostics = []
        sampler = perf.HostSampler(root, diagnostics)
        sampler.sample()
        self.assertFalse(sampler.result["complete"])
        self.assertIsNone(sampler.result["sampled_peak_rss_bytes"])
        self.assertEqual(sampler.result["sample_count"], 0)
        self.assertIn("AccessDenied", str(diagnostics))

    def test_child_disappears_and_known_child_remains_tracked(self):
        root, child = Mock(pid=123), Mock(pid=456)
        root.children.side_effect = [[child], []]
        root.memory_info.return_value.rss = 10
        child.children.return_value = []
        child.memory_info.side_effect = [Mock(rss=20), psutil.NoSuchProcess(456)]
        diagnostics = []
        sampler = perf.HostSampler(root, diagnostics)
        sampler.sample()
        sampler.sample()
        self.assertEqual(sampler.result["sampled_peak_rss_bytes"], 30)
        self.assertFalse(sampler.result["complete"])
        self.assertIn("NoSuchProcess", str(diagnostics))

    def test_normal_root_exit_during_sample_is_not_lost_child(self):
        root = Mock(pid=123)
        root.children.side_effect = psutil.NoSuchProcess(123)
        root.memory_info.side_effect = psutil.NoSuchProcess(123)
        diagnostics = []
        sampler = perf.HostSampler(root, diagnostics, root_exited=lambda: True)
        sampler.result["sample_count"] = 1
        sampler.result["sampled_peak_rss_bytes"] = 10
        sampler.sample()
        self.assertTrue(sampler.result["complete"])
        self.assertEqual(diagnostics, [])

    @unittest.skipUnless(os.name == "nt", "Windows Job Object lifecycle")
    def test_interrupt_kills_unobserved_child_after_root_exits(self):
        pid_file = Path(self.tmp.name) / "late-child.pid"
        code = (
            "import subprocess,sys,pathlib,time; "
            "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); "
            f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(.1)"
        )
        child_identity = []

        def exit_then_interrupt(sampler):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if pid_file.exists() and pid_file.read_text():
                    child_identity.append(psutil.Process(int(pid_file.read_text())))
                    root = next(iter(sampler.processes.values()))
                    root.wait(timeout=5)
                    # The exited parent may no longer be enumerable at cleanup time.
                    root.children = Mock(side_effect=psutil.NoSuchProcess(root.pid))
                    raise KeyboardInterrupt
                time.sleep(0.01)
            self.fail("local child did not start")

        try:
            with patch.object(
                perf.HostSampler, "sample", autospec=True, side_effect=exit_then_interrupt
            ):
                self.assertEqual(self.run_local(code), 130)
            child_identity[0].wait(timeout=3)
            self.assertFalse(child_identity[0].is_running())
        finally:
            for process in child_identity:
                if process.is_running():
                    process.kill()

    def test_interrupt_cleans_started_tree_and_saves_partial(self):
        with (
            patch.object(perf.HostSampler, "sample", side_effect=KeyboardInterrupt),
            patch.object(perf, "stop_tree", wraps=perf.stop_tree) as stop,
        ):
            self.assertEqual(self.run_local("import time; time.sleep(30)"), 130)
        stop.assert_called_once()
        data = self.read()
        self.assertTrue(data["partial"])
        self.assertFalse(data["host"]["complete"])
        self.assertIsNotNone(data["command_exit_code"])
        self.assertIsNotNone(stop.call_args.args[0].poll())

    def test_unexpected_collector_failure_cleans_command(self):
        with (
            patch.object(perf.HostSampler, "sample", side_effect=RuntimeError("secret")),
            patch.object(perf, "stop_tree", wraps=perf.stop_tree) as stop,
        ):
            self.assertEqual(self.run_local("import time; time.sleep(30)"), perf.COLLECTOR_ERROR)
        self.assertIsNotNone(stop.call_args.args[0].poll())
        self.assertTrue(self.read()["partial"])
        self.assertNotIn("secret", self.output.read_text())

    @unittest.skipUnless(os.name == "nt", "Windows Job Object lifecycle")
    def test_job_assignment_failure_cleans_suspended_command(self):
        with (
            patch.object(perf.WindowsJob, "assign", side_effect=PermissionError),
            patch.object(perf, "stop_tree", wraps=perf.stop_tree) as stop,
        ):
            self.assertEqual(self.run_local("import time; time.sleep(30)"), perf.COLLECTOR_ERROR)
        self.assertIsNotNone(stop.call_args.args[0].poll())
        self.assertTrue(self.read()["partial"])

    def test_output_publish_error_reports_original_exit(self):
        with patch.object(perf.os, "link", side_effect=OSError), patch("sys.stderr") as stderr:
            self.assertEqual(self.run_local("raise SystemExit(7)"), perf.COLLECTOR_ERROR)
        self.assertIn("command_exit_code=7", str(stderr.write.call_args_list))
        self.assertFalse(self.output.exists())
        self.assertEqual(list(Path(self.tmp.name).iterdir()), [])

    def test_atomic_publish_does_not_clobber_racing_writer(self):
        original_link = os.link

        def race(source, destination):
            Path(destination).write_text("winner", encoding="utf-8")
            original_link(source, destination)

        with patch.object(perf.os, "link", side_effect=race):
            self.assertEqual(self.run_local("pass"), perf.COLLECTOR_ERROR)
        self.assertEqual(self.output.read_text(), "winner")

    def test_command_uses_argv_no_shell_and_inherited_streams(self):
        real_popen = subprocess.Popen
        with patch.object(perf.subprocess, "Popen", wraps=real_popen) as launch:
            self.assertEqual(self.run_local("pass"), 0)
        args, kwargs = launch.call_args
        self.assertIsInstance(args[0], list)
        self.assertIs(kwargs["shell"], False)
        self.assertNotIn("stdout", kwargs)
        self.assertNotIn("stderr", kwargs)

    def test_fast_exit_or_unreadable_root_preserves_command_exit(self):
        real_init = psutil.Process.__init__
        calls = []

        def transient_discovery_failure(process, pid=None):
            if not calls:
                calls.append(pid)
                raise psutil.NoSuchProcess(pid)
            return real_init(process, pid)

        with patch.object(
            perf.psutil.Process, "__init__", autospec=True, side_effect=transient_discovery_failure
        ):
            self.assertEqual(self.run_local("raise SystemExit(7)"), 7)
        self.assertFalse(self.read()["host"]["complete"])
        self.assertIsNone(self.read()["host"]["sampled_peak_rss_bytes"])

    def test_launch_failure_still_saves_record(self):
        with patch.object(perf.subprocess, "Popen", side_effect=FileNotFoundError("secret")):
            self.assertEqual(self.run_local("pass"), perf.COLLECTOR_ERROR)
        self.assertIsNone(self.read()["command_exit_code"])
        self.assertTrue(self.read()["partial"])
        self.assertNotIn("secret", self.output.read_text())

    def test_cli_missing_dependency_has_collector_error(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "measure_competition_run.py"
        result = subprocess.run(  # noqa: S603 - local Python without site packages.
            [
                sys.executable,
                "-S",
                str(script),
                "--output",
                str(self.output),
                "--",
                sys.executable,
                "-c",
                "pass",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            shell=False,
        )
        self.assertEqual(result.returncode, perf.COLLECTOR_ERROR)
        self.assertIn("missing psutil", result.stderr)
        self.assertIn("command_exit_code=None", result.stderr)
        self.assertFalse(self.output.exists())

    def test_docker_samples_identity_limits_and_units_without_lifecycle_peak(self):
        diagnostics = []
        sampler = perf.ContainerSampler("sidecar", 0.2, diagnostics)
        metadata = {
            "id": "abc",
            "image": "sidecar:local",
            "image_id": "sha256:abc",
            "resource_limits": {"memory_bytes": 1024, "nano_cpus": 0},
        }
        stats = {"MemUsage": "12.5MiB / 1GiB", "CPUPerc": "120.25%"}
        with (
            patch.object(perf, "docker_json", side_effect=[metadata, stats]) as docker,
            patch.object(sampler.stop, "wait", return_value=True),
        ):
            sampler._run("docker")
        self.assertEqual(sampler.result["sampled_peak_memory_bytes"], 13107200)
        self.assertEqual(sampler.result["sampled_peak_cpu_percent"], 120.25)
        self.assertEqual(sampler.result["id"], "abc")
        self.assertEqual(sampler.result["resource_limits"]["memory_bytes"], 1024)
        self.assertTrue(sampler.result["complete"])
        self.assertNotIn("Config.Env", str(docker.call_args_list))
        self.assertNotIn("memory.peak", sampler.result)
        self.assertEqual(diagnostics, [])

    def test_docker_target_unavailable_or_stats_failure_is_null(self):
        for error in (
            FileNotFoundError(),
            subprocess.TimeoutExpired("docker", 2),
            subprocess.CalledProcessError(1, "docker"),
        ):
            diagnostics = []
            sampler = perf.ContainerSampler("sidecar", 0.2, diagnostics)
            with (
                self.subTest(error=type(error)),
                patch.object(perf, "docker_json", side_effect=error),
            ):
                sampler._run("docker")
            self.assertIsNone(sampler.result)
            self.assertTrue(diagnostics)

    def test_docker_partial_sample_is_marked_incomplete(self):
        sampler = perf.ContainerSampler("sidecar", 0.2, [])
        with (
            patch.object(
                perf,
                "docker_json",
                side_effect=[
                    {"id": "abc"},
                    {"MemUsage": "1MB / 2MB", "CPUPerc": "2%"},
                    PermissionError("secret"),
                ],
            ),
            patch.object(sampler.stop, "wait", return_value=False),
        ):
            sampler._run("docker")
        self.assertFalse(sampler.result["complete"])
        self.assertEqual(sampler.result["sample_count"], 1)
        self.assertNotIn("secret", str(sampler.diagnostics))

    def test_interrupt_kills_local_descendant(self):
        pid_file = Path(self.tmp.name) / "child.pid"
        child_code = "import time; time.sleep(30)"
        code = (
            "import subprocess,sys,time,pathlib; "
            f"p=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
            f"pathlib.Path({str(pid_file)!r}).write_text(str(p.pid)); time.sleep(30)"
        )
        child_identity = []

        def interrupt_when_child_exists(sampler):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if pid_file.exists() and pid_file.read_text():
                    child_identity.append(psutil.Process(int(pid_file.read_text())))
                    raise KeyboardInterrupt
                time.sleep(0.01)
            self.fail("local child did not start")

        with patch.object(
            perf.HostSampler, "sample", autospec=True, side_effect=interrupt_when_child_exists
        ):
            self.assertEqual(self.run_local(code), 130)
        self.assertFalse(child_identity[0].is_running())
        self.assertTrue(self.read()["partial"])


if __name__ == "__main__":
    unittest.main()
