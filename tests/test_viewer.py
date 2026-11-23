"""通过实际本机 HTTP 服务验证 DWS 审计文件的读取行为。"""

from contextlib import contextmanager
import json
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from urllib.request import ProxyHandler, build_opener


SERVER = Path(__file__).resolve().parents[1] / "server.py"
DAY_FILE = "audit-20260101.jsonl"
TIME = "2026-01-01T12:00:00.123456789+08:00"


@contextmanager
def running_viewer(*args):
    with subprocess.Popen(
        [sys.executable, str(SERVER), "--port", "0", *map(str, args)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    ) as process:
        try:
            if not select.select([process.stdout], [], [], 10)[0]:
                raise RuntimeError("等待审计服务启动超时")
            address = process.stdout.readline().strip()
            if not address.startswith("http://127.0.0.1:"):
                raise RuntimeError(f"服务未能启动：{address}")
            client = build_opener(ProxyHandler({}))

            def get(path):
                with client.open(address.rstrip("/") + path, timeout=5) as response:
                    return response.read()

            yield get
        finally:
            process.terminate()
            process.wait(timeout=5)


def append_event(directory, event):
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / DAY_FILE).open("a", encoding="utf-8") as out:
        out.write(json.dumps(event) + "\n")


class ViewerTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.audit_dir = Path(tmp.name) / "audit"

    def test_bundled_demo_shows_only_demo_events(self):
        with running_viewer("--demo") as get:
            data = json.loads(get("/api/audit"))
        self.assertEqual([s["id"] for s in data["sources"]], ["demo"])
        self.assertEqual(data["issues"], [])
        commands = {r["event"]["command_path"]: r["event"] for r in data["commands"]}
        tools = {r["event"]["execution_id"]: r["event"]["command"] for r in data["tools"]}
        sent = commands["chat/+messages-send"]
        self.assertEqual([tools[i] for i in sent["tool_execution_ids"]],
                         ["send_personal_message", "query_message_send_status"])
        self.assertEqual(commands["report"]["exit_code"], 0)
        self.assertEqual(commands["report"]["policy"]["reason_code"], "all_children_denied")

    def test_empty_directory_then_legacy_tool_log(self):
        with running_viewer("--audit-dir", self.audit_dir) as get:
            self.assertIn("审计".encode(), get("/"))
            empty = json.loads(get("/api/audit"))
            self.assertEqual(empty["commands"], [])
            self.assertEqual(empty["tools"], [])
            self.assertFalse(self.audit_dir.exists())

            append_event(self.audit_dir, {
                "ts": TIME, "execution_id": "tool-1", "result": "success",
                "actor": {"name": "private-example"}, "params_summary": "private-example",
                "endpoint": "private-example", "error_reason": "private-example",
            })
            response = get("/api/audit")
            self.assertNotIn(b"private-example", response)
            snapshot = json.loads(response)
            self.assertEqual(snapshot["commands"], [])
            self.assertEqual(snapshot["tools"][0]["event"]["execution_id"], "tool-1")
            self.assertEqual(snapshot["sources"][0]["tool_count"], 1)

    def test_command_policy_and_tool_references(self):
        append_event(self.audit_dir, {"ts": TIME, "execution_id": "tool-1"})
        command_dir = self.audit_dir / "commands"
        append_event(command_dir, {
            "ts": TIME, "event_type": "command.finished", "command_id": "cmd-1",
            "command_path": "calendar/event/list", "result": "success", "exit_code": 0,
            "tool_execution_ids": ["tool-1"], "argv": ["private-example"],
        })
        policy = {"decision": "deny", "reason_code": "all_children_denied", "target_path": "report"}
        append_event(command_dir, {
            "ts": TIME, "event_type": "command.finished", "command_id": "cmd-2",
            "command_path": "report", "surface": "help", "result": "success", "exit_code": 0,
            "policy": dict(policy, details="private-example"), "tool_execution_ids": [],
        })
        with running_viewer("--audit-dir", self.audit_dir) as get:
            response = get("/api/audit")
        self.assertNotIn(b"private-example", response)
        data = json.loads(response)
        self.assertEqual(data["issues"], [])
        commands = {row["event"]["command_id"]: row for row in data["commands"]}
        tool, = data["tools"]
        self.assertEqual(commands["cmd-1"]["source"], tool["source"])
        self.assertEqual(commands["cmd-1"]["event"]["tool_execution_ids"], [tool["event"]["execution_id"]])
        self.assertEqual(commands["cmd-2"]["event"]["exit_code"], 0)
        self.assertEqual(commands["cmd-2"]["event"]["policy"], policy)

    def test_refresh_only_emits_complete_lines(self):
        self.audit_dir.mkdir()
        path = self.audit_dir / DAY_FILE
        path.write_text('{"ts":"' + TIME + '","execution_id":', encoding="utf-8")
        with running_viewer("--audit-dir", self.audit_dir) as get:
            first = json.loads(get("/api/audit"))
            self.assertEqual(first["tools"], [])
            self.assertTrue(first["issues"])
            with path.open("a", encoding="utf-8") as out:
                out.write('"tool-2"}\n')
            second = json.loads(get("/api/audit"))
            self.assertEqual(second["issues"], [])
            self.assertEqual([row["event"]["execution_id"] for row in second["tools"]], ["tool-2"])

    def test_configured_sources_keep_their_ids(self):
        sources = []
        for name in ("first", "second"):
            directory = self.audit_dir / name
            sources.append({"id": name, "label": name, "path": str(directory)})
            append_event(directory, {"ts": TIME, "execution_id": "shared-id", "product": name})
        config = self.audit_dir.parent / "sources.json"
        config.write_text(json.dumps(sources), encoding="utf-8")
        with running_viewer("--sources", config) as get:
            data = json.loads(get("/api/audit"))
        self.assertEqual({row["source"]: row["event"]["product"] for row in data["tools"]},
                         {"first": "first", "second": "second"})
        self.assertEqual({s["id"]: s["tool_count"] for s in data["sources"]}, {"first": 1, "second": 1})


if __name__ == "__main__":
    unittest.main()
