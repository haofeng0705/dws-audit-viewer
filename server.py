#!/usr/bin/env python3
"""DWS 本地审计工作台。从审计目录读取命令与工具事件。"""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit


STATIC_DIR = Path(__file__).resolve().parent
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
FILE_NAME = re.compile(r"audit-[0-9]{8}\.jsonl")
MAX_FILES = 14
MAX_BYTES = 4 * 1024 * 1024
MAX_EVENTS = 1000
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
COMMON = ("ts", "result", "duration_ms", "cli_version", "hash", "prev_hash", "error_category")
COMMAND = COMMON + ("event_type", "command_id", "command_path", "surface", "exit_code", "error_reason")
# 工具 error_reason 在旧版日志中可以是完整错误，参数摘要也可能含业务内容。
TOOL = COMMON + ("execution_id", "product", "command", "os", "arch")
POLICY = ("state", "decision", "source", "view_hash", "target_path", "rule_name", "reason_code")


@contextmanager
def open_directory(path, parent_fd=None):
    if parent_fd is None:
        # 固定路径逐段打开，防止配置解析之后有上级目录被换成符号链接。
        full = Path(path)
        fd = os.open(full.anchor, DIR_FLAGS)
        try:
            for part in full.parts[1:]:
                child = os.open(part, DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
        except BaseException:
            os.close(fd)
            raise
    else:
        fd = os.open(path, DIR_FLAGS, dir_fd=parent_fd)
    try:
        yield fd
    finally:
        os.close(fd)


def select_fields(obj, names):
    return {k: obj[k] for k in names if type(obj.get(k)) in (int, str)}


def event_view(record, is_command):
    if not isinstance(record, dict):
        raise ValueError()
    identity = record.get("command_id" if is_command else "execution_id")
    if not isinstance(identity, str) or not identity or not isinstance(record.get("ts"), str):
        raise ValueError()
    # Go time.Time 带时区。转换为统一时刻再排序，可比较不同时区的来源。
    # macOS 自带的 Python 3.9 只接受三位或六位分数秒，Go 可能输出一到九位。
    stamp = re.sub(r"(?<=\d)\.(\d{1,9})(?=Z|[+-])", lambda match: "." + match[1][:6].ljust(6, "0"), record["ts"])
    timestamp = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if timestamp.tzinfo is None:
        raise ValueError()
    event = select_fields(record, COMMAND if is_command else TOOL)
    if is_command:
        if record.get("event_type") != "command.finished":
            raise ValueError()
        if isinstance(record.get("policy"), dict):
            event["policy"] = select_fields(record["policy"], POLICY)
        ids = record.get("tool_execution_ids")
        event["tool_execution_ids"] = [i for i in ids if isinstance(i, str)] if isinstance(ids, list) else []
    return timestamp, event


def read_stream(directory, is_command):
    stream = "命令" if is_command else "工具"
    names = sorted((name for name in os.listdir(directory) if FILE_NAME.fullmatch(name)), reverse=True)
    remaining = MAX_BYTES
    events = []
    notes = []
    invalid = unreadable = partial_lines = 0
    truncated = len(names) > MAX_FILES
    for name in names[:MAX_FILES]:
        if remaining == 0 or len(events) == MAX_EVENTS:
            truncated = True
            break
        try:
            # 相对已打开的目录定位文件，禁止符号链接，也不阻塞在管道文件上。
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    raise OSError()
                size = min(info.st_size, remaining)
                offset = info.st_size - size
                # 多读一字节区分恰好切在换行后和切在行中间。
                start = max(0, offset - 1)
                tail = os.pread(fd, info.st_size - start, start)
                if offset:
                    truncated = True
                    border, tail = tail[:1], tail[1:]
                    if border != b"\n":
                        tail = tail.partition(b"\n")[2]
                remaining -= size
            finally:
                os.close(fd)
        except OSError:
            unreadable += 1
            continue
        # 写入中的末行留待下次轮询，JSON 只在换行后解析。
        if tail and not tail.endswith(b"\n"):
            partial_lines += 1
            tail = tail.rpartition(b"\n")[0]
        for line in reversed(tail.split(b"\n")):
            if not line:
                continue
            if len(events) == MAX_EVENTS:
                truncated = True
                break
            try:
                events.append(event_view(json.loads(line), is_command))
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                invalid += 1
    if truncated:
        notes.append(f"{stream}日志展示最近窗口，每个来源最多读取 {MAX_FILES} 个日文件、4 MiB、{MAX_EVENTS} 条事件。")
    if invalid:
        notes.append(f"{stream}日志跳过 {invalid} 条格式异常记录。")
    if unreadable:
        notes.append(f"{stream}日志有 {unreadable} 个文件无法读取。")
    if partial_lines:
        notes.append(f"{stream}日志有未写完的末行，将在下一次刷新时重读。")
    return events, notes


def get_snapshot(sources):
    output = {"sources": [], "commands": [], "tools": [], "issues": []}
    rows = {"commands": [], "tools": []}
    for item in sources:
        source = {k: item[k] for k in ("id", "label")}
        source.update(command_count=0, tool_count=0)
        output["sources"].append(source)

        def collect(directory, kind):
            commands = kind == "commands"
            entries, notes = read_stream(directory, commands)
            source["command_count" if commands else "tool_count"] = len(entries)
            rows[kind].extend((ts, {"source": source["id"], "event": ev}) for ts, ev in entries)
            for note in notes:
                output["issues"].append({"source": source["id"], "message": note})

        try:
            with open_directory(item["path"]) as base:
                collect(base, "tools")
                try:
                    with open_directory("commands", base) as directory:
                        collect(directory, "commands")
                except FileNotFoundError:
                    pass
        except FileNotFoundError:
            # 目录由 CLI 在首次写入时创建，下一次轮询会重新打开。
            continue
        except OSError:
            output["issues"].append({"source": source["id"], "message": "审计目录暂时无法读取。"})
    for kind, entries in rows.items():
        entries.sort(key=lambda pair: pair[0], reverse=True)
        output[kind] = [wrapped for _, wrapped in entries]
    output["updated_at"] = datetime.now(timezone.utc).isoformat()
    return output


class Viewer(BaseHTTPRequestHandler):
    def __init__(self, *args, sources, **kwargs):
        self.sources = sources
        super().__init__(*args, **kwargs)

    def do_GET(self):
        self.serve_content()

    def do_HEAD(self):
        self.serve_content()

    def serve_content(self):
        port = self.server.server_port
        hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if port == 80:
            hosts.update(("127.0.0.1", "localhost"))
        sent_hosts = self.headers.get_all("Host", [])
        if len(sent_hosts) != 1 or sent_hosts[0] not in hosts:
            return self.send_error(403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site" and self.headers.get("Sec-Fetch-Mode") != "navigate":
            return self.send_error(403)
        try:
            route = urlsplit(self.path)
        except ValueError:
            return self.send_error(400)
        if route.scheme or route.netloc:
            return self.send_error(400)
        if route.path == "/api/audit":
            data = json.dumps(get_snapshot(self.sources), ensure_ascii=True, separators=(",", ":")).encode()
            content_type = "application/json; charset=utf-8"
        elif route.path in STATIC:
            filename, content_type = STATIC[route.path]
            try:
                data = (STATIC_DIR / filename).read_bytes()
            except OSError:
                return self.send_error(404)
        else:
            return self.send_error(404)
        self.send_response(200)
        self.send_header("X-DWS-Audit-Viewer", "1")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if self.command == "GET":
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        super().end_headers()

    def log_message(self, format, *args):
        # 不保留访问记录，防止查询字符串误带敏感内容。
        pass


def read_sources(path=None, audit_dir=None, *, demo=False):
    if path is not None:
        sources = json.loads(Path(path).read_text(encoding="utf-8"))
    elif demo:
        sources = [{"id": "demo", "label": "演示数据", "path": str(STATIC_DIR / "examples" / "demo")}]
    else:
        root = audit_dir or os.environ.get("DWS_AUDIT_DIR")
        if not root:
            config_dir = os.environ.get("DWS_CONFIG_DIR") or "~/.dws"
            root = Path(config_dir) / "audit"
        sources = [{
            "id": "daily",
            "label": "本机审计日志",
            "path": str(Path(root).expanduser().absolute()),
        }]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 20:
        raise ValueError("请配置 1 到 20 个来源")
    ids = set()
    for item in sources:
        if not isinstance(item, dict) or not all(isinstance(item.get(k), str) and item[k].strip() for k in ("id", "label", "path")):
            raise ValueError("来源必须填写 id、label、path")
        if item["id"] in ids:
            raise ValueError("来源 id 必须唯一")
        ids.add(item["id"])
        root = Path(item["path"]).expanduser()
        if not root.is_absolute():
            raise ValueError("来源目录必须是绝对路径")
        # 配置可使用 macOS 的 /var 别名。只解析受信的上级目录，
        # 审计根本身和其下的条目在每一次打开时均禁止跟随符号链接。
        item["path"] = root.parent.resolve() / root.name
    return sources


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument(
        "--audit-dir", metavar="DIR",
        help="指定审计目录。默认依次读取 DWS_AUDIT_DIR、DWS_CONFIG_DIR 下的 audit、~/.dws/audit",
    )
    inputs.add_argument("--sources", metavar="FILE", help="读取 JSON 配置中的多个日志源")
    inputs.add_argument("--demo", action="store_true", help="只展示仓库内的虚构演示数据")
    parser.add_argument("--port", type=int, default=18765, help="本机监听端口（默认 18765）")
    args = parser.parse_args()
    try:
        config = read_sources(args.sources, args.audit_dir, demo=args.demo)
        server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Viewer, sources=config))
    except (OSError, ValueError, OverflowError) as err:
        parser.exit(1, f"启动失败：{err}\n")
    print(f"http://127.0.0.1:{server.server_port}/", flush=True)
    with server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
