"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { callGroupKey, groupCalls } = require("../app.js");

function command(source, id, path, result = "success") {
  return { source, event: { command_id: id, command_path: path, result } };
}

function tool(source, id, product, name) {
  return { source, event: { execution_id: id, product, command: name } };
}

test("跨页和跨来源的同名命令按最近一次出现的位置合并，保留每次调用", () => {
  const newest = command("local", "first", "calendar/event/list");
  const other = Array.from({ length: 12 }, (_, i) =>
    command("local", "event-" + i, "example/command-" + i),
  );
  const oldest = command("test", "last", "calendar/event/list", "failure");
  const groups = groupCalls([newest, ...other, oldest], "commands");

  assert.equal(typeof groups[0].key, "string");
  assert.equal(groups[0].key, callGroupKey("commands", oldest));
  assert.deepEqual(
    groups.map((group) => group.rows),
    [[newest, oldest], ...other.map((row) => [row])],
  );
});

test("同一产品的同名工具合并，其他产品的同名工具独立展示", () => {
  const first = tool("local", "t1", "calendar", "list");
  const second = tool("local", "t2", "drive", "list");
  const third = tool("test", "t3", "calendar", "list");

  assert.notEqual(callGroupKey("tools", first), callGroupKey("tools", second));
  assert.deepEqual(
    groupCalls([first, second, third], "tools").map((group) => group.rows),
    [[first, third], [second]],
  );
});

test("没有命令路径或工具名称时，每条记录保持独立", () => {
  const commands = [
    command("local", "c1", undefined, "failure"),
    command("local", "c2", undefined, "failure"),
  ];
  const tools = [
    tool("test", "t1", "calendar", ""),
    tool("test", "t2", "calendar", ""),
  ];
  for (const [kind, events] of [
    ["commands", commands],
    ["tools", tools],
  ]) {
    assert.equal(callGroupKey(kind, events[0]), null);
    assert.deepEqual(
      groupCalls(events, kind).map((group) => group.rows),
      [[events[0]], [events[1]]],
    );
  }
});
