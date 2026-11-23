"use strict";

const $ = (id) => document.getElementById(id);
const pageSize = 12;
const state = {
  data: { sources: [], commands: [], tools: [], issues: [] },
  view: "commands",
  source: "",
  search: "",
  result: "",
  decision: "",
  page: 1,
  grouped: false,
  groupDetail: null,
  selection: null,
  loading: false,
  loaded: false,
};
const views = { commands: "命令事件", denied: "策略拒绝", tools: "工具调用" };
const surfaces = {
  execute: "命令执行",
  policy_inspect: "策略查询",
  help: "帮助查询",
  schema: "Schema 查询",
  unresolved: "未解析",
};
const policyStates = {
  disabled: "未启用",
  active: "已启用",
  invalid: "策略无效",
};
const reasons = {
  domain_not_allowed: "路径不在规则允许范围内",
  command_denylisted: "命中规则的拒绝清单",
  risk_too_high: "操作影响或风险超过规则上限",
  risk_not_annotated: "缺少影响或风险声明",
  risk_invalid: "影响或风险声明无效",
  channel_not_allowed: "规则未允许此通道入口",
  no_matching_rule: "没有放行此操作的规则",
  identity_conflict: "无法可靠判断命令归属",
  all_children_denied: "分组下的命令均被裁剪",
  policy_invalid: "策略配置无效",
};
const plural = new Intl.NumberFormat("zh-CN");
let sourceLabels = new Map();
let lastDrawerKey = "";

function element(tag, className, content) {
  const out = document.createElement(tag);
  if (className) out.className = className;
  if (content !== null && content !== undefined)
    out.textContent = String(content);
  return out;
}
function icon(name, extra = "") {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "icon " + extra);
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(ns, "use");
  use.setAttribute("href", "#i-" + name);
  svg.append(use);
  return svg;
}
function eventId(kind, row) {
  return kind === "tools" ? row.event.execution_id : row.event.command_id;
}
function commandTitle(e) {
  return (
    e.command_path ||
    (e.surface === "unresolved" ? "未解析的命令" : "无命令路径")
  );
}
function toolTitle(e) {
  return [e.product, e.command].filter(Boolean).join(" / ") || "未命名工具";
}
function eventTitle(kind, e) {
  return kind === "tools" ? toolTitle(e) : commandTitle(e);
}
function callGroupKey(kind, row) {
  const e = row.event;
  if (kind === "tools")
    return e.command ? JSON.stringify([e.product || "", e.command]) : null;
  return e.command_path || null;
}
function groupCalls(rows, kind) {
  const groups = [];
  const named = new Map();
  for (const row of rows) {
    const key = callGroupKey(kind, row);
    let group = named.get(key);
    if (!group) {
      group = { key, rows: [] };
      groups.push(group);
      if (key !== null) named.set(key, group);
    }
    group.rows.push(row);
  }
  return groups;
}
function isInScope(row) {
  return !state.source || row.source === state.source;
}
function labelSource(id) {
  return sourceLabels.get(id) || id || "—";
}
function statusInfo(raw) {
  if (raw === "success")
    return { key: "success", label: "成功", color: "green" };
  if (["failure", "error", "failed"].includes(raw))
    return { key: "failure", label: "失败", color: "red" };
  return { key: raw || "", label: raw || "未记录", color: "gray" };
}
function policyInfo(p) {
  if (p?.decision === "deny") return { label: "拒绝", color: "gold" };
  if (p?.decision === "allow") return { label: "放行", color: "green" };
  if (p?.decision === "not_evaluated")
    return { label: "未判定", color: "gray" };
  return { label: p?.decision || "无记录", color: "gray" };
}
function badge(info) {
  return element("span", "badge " + info.color, info.label);
}
function formatTime(ts) {
  const date = new Date(ts);
  if (Number.isNaN(date.getTime())) return { time: "—", date: "—" };
  const pad = (n) => String(n).padStart(2, "0");
  return {
    date: [
      date.getFullYear(),
      pad(date.getMonth() + 1),
      pad(date.getDate()),
    ].join("-"),
    time: [
      pad(date.getHours()),
      pad(date.getMinutes()),
      pad(date.getSeconds()),
    ].join(":"),
  };
}
function duration(ms) {
  if (typeof ms !== "number") return "—";
  return ms < 1000
    ? ms + " ms"
    : (ms / 1000).toLocaleString("zh-CN", { maximumFractionDigits: 3 }) + " s";
}
function renderSources() {
  const sel = $("sources");
  const options = state.data.sources.map((source) => [source.id, source.label]);
  if (options.length !== 1) options.unshift(["", "全部日志源"]);
  if (!options.some(([id]) => id === state.source)) state.source = options[0][0];
  const now = JSON.stringify(options);
  if (sel.dataset.signature !== now) {
    sel.replaceChildren(
      ...options.map(([value, name]) => new Option(name, value)),
    );
    sel.dataset.signature = now;
  }
  sel.value = state.source;
  $("sidebar-source-count").textContent =
    plural.format(state.data.sources.length) + " 个日志源";
}
function renderMetrics(commands, tools) {
  const successful = commands.filter(
    (r) => r.event.result === "success",
  ).length;
  const denied = commands.filter((r) => r.event.policy?.decision === "deny");
  const failed = commands.filter(
    (r) => statusInfo(r.event.result).key === "failure",
  ).length;
  const counts = {
    commands: commands.length,
    success: successful,
    denied: denied.length,
    tools: tools.length,
  };
  for (const [name, value] of Object.entries(counts))
    $("m-" + name).textContent = plural.format(value);
  $("f-commands").textContent = "其中 " + plural.format(failed) + " 次执行失败";
  $("f-success").textContent = commands.length
    ? "占命令事件 " + ((successful * 100) / commands.length).toFixed(1) + "%"
    : "当前日志源暂无命令";
  const blocked = denied.filter((r) => r.event.surface === "execute").length;
  $("f-denied").textContent = plural.format(blocked) + " 次命令执行被拒绝";
  const linked = new Set();
  commands.forEach((r) =>
    (r.event.tool_execution_ids || []).forEach((id) =>
      linked.add(JSON.stringify([r.source, id])),
    ),
  );
  $("f-tools").textContent =
    plural.format(
      tools.filter((r) =>
        linked.has(JSON.stringify([r.source, r.event.execution_id])),
      ).length,
    ) + " 条已关联命令";
  $("nav-denied").textContent = plural.format(denied.length);
  $("nav-denied").hidden = !denied.length;
}
function searchable(row, kind) {
  const e = row.event,
    p = e.policy || {};
  return [
    eventTitle(kind, e),
    e.command_path?.replaceAll("/", " "),
    eventId(kind, row),
    e.surface,
    surfaces[e.surface],
    e.product,
    e.command,
    e.result,
    e.error_category,
    e.error_reason,
    e.ts,
    p.decision,
    p.target_path,
    p.rule_name,
    p.reason_code,
    reasons[p.reason_code],
    labelSource(row.source),
    ...(e.tool_execution_ids || []),
  ]
    .filter(Boolean)
    .join(" ")
    .toLocaleLowerCase();
}
function filterRows(rows, kind) {
  const query = state.search.trim().toLocaleLowerCase();
  return rows
    .filter((row) => {
      const e = row.event;
      if (state.view === "denied" && e.policy?.decision !== "deny")
        return false;
      if (state.result && statusInfo(e.result).key !== state.result)
        return false;
      if (
        state.view === "commands" &&
        state.decision &&
        (e.policy?.decision || "missing") !== state.decision
      )
        return false;
      return !query || searchable(row, kind).includes(query);
    })
    .sort((a, b) => Date.parse(b.event.ts) - Date.parse(a.event.ts));
}
function dualCell(
  primary,
  secondary,
  primaryClass = "primary",
  secondaryClass = "secondary",
) {
  const cell = element("td");
  cell.append(element("span", primaryClass, primary));
  if (secondary) cell.append(element("span", secondaryClass, secondary));
  return cell;
}
function rowNode(row, kind) {
  const e = row.event,
    isTool = kind === "tools",
    tr = element("tr");
  tr.dataset.row = "true";
  const title = eventTitle(kind, e),
    action = element("button", "row-btn", title);
  action.setAttribute("aria-label", "查看详情 " + title);
  const nameTd = element("td"),
    name = element("span", "primary");
  name.append(action);
  nameTd.append(name);
  nameTd.append(
    element(
      "span",
      "secondary",
      isTool
        ? e.error_category || e.product || ""
        : surfaces[e.surface] || e.surface || "",
    ),
  );
  const t = formatTime(e.ts);
  tr.append(dualCell(t.time, t.date, "time"), nameTd);
  const result = element("td");
  result.append(badge(statusInfo(e.result)));
  if (!isTool && e.exit_code !== undefined)
    result.append(element("span", "secondary", "退出 " + e.exit_code));
  tr.append(result);
  if (!isTool) {
    const policy = element("td", "desktop-compact");
    policy.append(badge(policyInfo(e.policy)));
    const secondary = e.policy?.reason_code || e.policy?.rule_name;
    if (secondary) policy.append(element("span", "secondary mono", secondary));
    tr.append(policy);
  }
  tr.append(dualCell(duration(e.duration_ms), null, "duration"));
  const source = element("td");
  source.append(element("span", "source-name", labelSource(row.source)));
  tr.append(source);
  const arrow = element("td");
  arrow.append(icon("chevron", "arrow"));
  tr.append(arrow);
  tr.addEventListener("click", () => openDetails(kind, row));
  return tr;
}
function countsCell(rows, infoFor, className = "") {
  const counts = new Map();
  for (const { event } of rows) {
    const info = infoFor(event);
    const entry = counts.get(info.label);
    if (entry) entry.count++;
    else counts.set(info.label, { info, count: 1 });
  }
  const cell = element("td", className);
  const badges = element("div", "group-counts");
  for (const { info, count } of counts.values()) {
    const label = info.label + " × " + plural.format(count);
    badges.append(badge({ ...info, label }));
  }
  cell.append(badges);
  return cell;
}
function groupedRow(group, kind) {
  const { rows } = group;
  if (rows.length === 1) return rowNode(rows[0], kind);

  const tr = element("tr");
  tr.dataset.row = "true";
  const title = eventTitle(kind, rows[0].event);
  const action = element("button", "row-btn", title);
  action.dataset.groupKey = group.key;
  const count = plural.format(rows.length);
  action.append(element("span", "repeat-count", "× " + count));
  action.setAttribute("aria-label", "查看 " + title + " 的 " + count + " 次调用");
  const name = element("td");
  name.append(action);
  const time = formatTime(rows[0].event.ts);
  tr.append(
    dualCell(time.time, time.date, "time"),
    name,
    countsCell(rows, (e) => statusInfo(e.result)),
  );
  if (kind === "commands")
    tr.append(countsCell(rows, (e) => policyInfo(e.policy), "desktop-compact"));

  let min = Infinity;
  let max = -Infinity;
  const sources = new Set();
  for (const row of rows) {
    const ms = row.event.duration_ms;
    if (Number.isFinite(ms)) {
      min = Math.min(min, ms);
      max = Math.max(max, ms);
    }
    sources.add(row.source);
  }
  let elapsed = "—";
  if (min !== Infinity) {
    elapsed = min === max ? duration(min) : duration(min) + "–" + duration(max);
  }
  const source = sources.size === 1
    ? labelSource(rows[0].source)
    : sources.size + " 个来源";
  tr.append(
    dualCell(elapsed, null, "duration"),
    dualCell(source, null, "source-name"),
  );
  const arrow = element("td");
  arrow.append(icon("chevron", "arrow"));
  tr.append(arrow);
  tr.addEventListener("click", () => {
    state.groupDetail = { key: group.key, returnPage: state.page };
    state.page = 1;
    render();
    $("back-to-groups").focus();
  });
  return tr;
}
function renderTable(commands, tools) {
  const inTools = state.view === "tools",
    kind = inTools ? "tools" : "commands";
  const filtered = filterRows(inTools ? tools : commands, kind);
  const groups = state.grouped ? groupCalls(filtered, kind) : null;
  const detail = state.groupDetail &&
    groups?.find((group) => group.key === state.groupDetail.key);
  if (state.groupDetail && !detail) {
    state.page = state.groupDetail.returnPage;
    state.groupDetail = null;
  }
  const summary = state.grouped && !detail;
  const list = detail?.rows ?? groups ?? filtered;
  $("group-trail").hidden = !detail;
  if (detail) {
    const title = eventTitle(kind, detail.rows[0].event);
    $("group-caption").textContent = title + " × " + plural.format(detail.rows.length);
  }
  const pages = Math.max(1, Math.ceil(list.length / pageSize));
  state.page = Math.min(state.page, pages);
  const offset = (state.page - 1) * pageSize;
  $("view-title").textContent = views[state.view];
  $("result-count").textContent = summary
    ? plural.format(list.length) + " 组 · " + plural.format(filtered.length) + " 次调用"
    : plural.format(list.length);
  $("policy-wrap").hidden = state.view !== "commands";
  $("search").placeholder = inTools
    ? "搜索工具、产品或执行 ID"
    : "搜索命令、规则或事件 ID";
  document.querySelectorAll("[data-view]").forEach((b) => {
    const active = b.dataset.view === state.view;
    b.classList.toggle("active", active);
    if (active) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  const cols = inTools
    ? ["发生时间", "工具名称", "执行结果", "耗时", "日志源", ""]
    : ["发生时间", "命令路径", "执行结果", "策略判定", "耗时", "日志源", ""];
  if (summary) cols[0] = "最近时间";
  $("table-head").replaceChildren(...cols.map((c) => element("th", "", c)));
  const renderRow = summary ? groupedRow : rowNode;
  $("rows").replaceChildren(
    ...list.slice(offset, offset + pageSize).map((row) => renderRow(row, kind)),
  );
  $("empty").hidden = list.length > 0;
  const hasFilters = Boolean(
    state.search ||
    state.result ||
    (state.view === "commands" && state.decision),
  );
  $("empty-title").textContent = hasFilters
    ? "没有匹配的记录"
    : state.view === "denied"
      ? "当前日志源暂无策略拒绝"
      : "当前日志源暂无" + views[state.view];
  let emptyHint;
  if (hasFilters) {
    emptyHint = "可调整搜索词或清空筛选。";
  } else if (!commands.length && !tools.length) {
    emptyHint = "请确认 DWS 已开启审计，并与工作台使用同一日志目录。执行一条可审计的命令后，点击「刷新」。";
  } else if (!commands.length) {
    emptyHint = "当前读到了工具日志，可切换到「工具调用」查看。旧版 DWS 只写工具日志，命令事件需要支持命令审计的版本。";
  } else if (state.view === "denied") {
    emptyHint = "当前读取的命令记录中没有策略拒绝。可切换到「命令事件」查看各次判定。";
  } else {
    emptyHint = "执行一次会产生工具审计记录的 DWS 调用后，点击「刷新」。";
  }
  $("empty-text").textContent = emptyHint;
  $("clear").hidden = !hasFilters;
  $("showing").textContent = list.length
    ? "显示 " +
      (offset + 1) +
      "–" +
      Math.min(offset + pageSize, list.length) +
      "，共 " +
      plural.format(list.length) +
      (summary ? " 组" : " 条")
    : (summary ? "共 0 组" : "共 0 条");
  $("page").textContent = state.page + " / " + pages;
  $("prev").disabled = state.page <= 1;
  $("next").disabled = state.page >= pages;
}
function render() {
  sourceLabels = new Map(state.data.sources.map((s) => [s.id, s.label]));
  renderSources();
  const commands = state.data.commands.filter(isInScope),
    tools = state.data.tools.filter(isInScope);
  renderMetrics(commands, tools);
  renderTable(commands, tools);
  const issues = state.data.issues.filter(isInScope);
  $("warnings").hidden = !issues.length;
  $("warnings-title").textContent = "日志读取提示（" + issues.length + "）";
  $("warning-items").replaceChildren(
    ...issues.map((issue) =>
      element("li", "", labelSource(issue.source) + " · " + issue.message),
    ),
  );
  renderDrawer();
}
function infoBlock(title, fields) {
  const group = element("section", "detail-box"),
    list = element("dl");
  group.append(element("h3", "", title), list);
  fields.forEach(([label, value]) => {
    if (value === undefined || value === null || value === "") return;
    const dd = element("dd");
    if (value instanceof Node) dd.append(value);
    else dd.textContent = String(value);
    list.append(element("dt", "", label), dd);
  });
  return group;
}
function openDetails(kind, row) {
  state.selection = { kind, source: row.source, id: eventId(kind, row) };
  lastDrawerKey = "";
  renderDrawer();
  if (!$("drawer").open) $("drawer").showModal();
  $("drawer").scrollTop = 0;
  $("detail-title").focus({ preventScroll: true });
}
function linkedEvents(kind, row) {
  if (kind === "commands") {
    const tools = new Map(
      state.data.tools
        .filter((r) => r.source === row.source)
        .map((r) => [r.event.execution_id, r]),
    );
    return (row.event.tool_execution_ids || []).map((id) => ({
      id,
      row: tools.get(id),
      kind: "tools",
    }));
  }
  return state.data.commands
    .filter(
      (r) =>
        r.source === row.source &&
        r.event.tool_execution_ids?.includes(row.event.execution_id),
    )
    .map((r) => ({ id: r.event.command_id, row: r, kind: "commands" }));
}
function linksBlock(kind, links) {
  const box = element("section", "detail-box"),
    parent = element("div", "detail-links");
  box.append(
    element("h3", "", kind === "commands" ? "关联工具调用" : "关联命令事件"),
    parent,
  );
  if (!links.length)
    parent.append(
      element(
        "p",
        "detail-muted",
        kind === "commands"
          ? "此命令没有记录关联工具 ID。"
          : "当前日志源未找到关联命令。",
      ),
    );
  links.forEach((link) => {
    if (!link.row) {
      parent.append(
        element("p", "detail-muted", link.id + " · 当前日志源未找到工具记录"),
      );
      return;
    }
    const button = element(
      "button",
      "detail-link",
      eventTitle(link.kind, link.row.event),
    );
    button.append(icon("chevron"));
    button.addEventListener("click", () => openDetails(link.kind, link.row));
    parent.append(button);
  });
  return box;
}
function renderDrawer() {
  const sel = state.selection;
  if (!sel) return;
  const row = state.data[sel.kind].find(
    (r) => r.source === sel.source && eventId(sel.kind, r) === sel.id,
  );
  if (!row) {
    $("detail-body").replaceChildren(
      element("p", "detail-muted", "刷新后的日志中已找不到此条记录。"),
    );
    lastDrawerKey = "";
    return;
  }
  const e = row.event,
    isTool = sel.kind === "tools",
    links = linkedEvents(sel.kind, row);
  const signature = JSON.stringify([
    sel,
    e,
    labelSource(row.source),
    links.map((l) => [l.id, l.row && eventTitle(l.kind, l.row.event)]),
  ]);
  if (signature === lastDrawerKey) return;
  const preserveJson =
    lastDrawerKey && $("detail-body").querySelector("details")?.open;
  lastDrawerKey = signature;
  $("detail-title").textContent = eventTitle(sel.kind, e);
  $("detail-kind").textContent = isTool ? "工具调用详情" : "命令事件详情";
  const t = formatTime(e.ts);
  const group = infoBlock("执行信息", [
    ["执行结果", badge(statusInfo(e.result))],
    ["退出码", e.exit_code],
    ["发生时间", t.date + " " + t.time],
    ["耗时", duration(e.duration_ms)],
    ["调用入口", surfaces[e.surface] || e.surface],
    ["日志源", labelSource(row.source)],
    ["CLI 版本", e.cli_version],
    [isTool ? "工具执行 ID" : "命令 ID", eventId(sel.kind, row)],
    ["错误类别", e.error_category],
    ["错误原因", e.error_reason],
  ]);
  const body = $("detail-body");
  body.replaceChildren(group);
  if (!isTool) {
    const p = e.policy;
    const pb = infoBlock("指令裁剪策略", [
      ["策略判定", badge(policyInfo(p))],
      ["策略状态", policyStates[p?.state] || p?.state],
      ["作用目标", p?.target_path],
      ["规则名称", p?.rule_name],
      ["拒绝原因码", p?.reason_code],
      ["策略来源", p?.source],
      ["策略视图哈希", p?.view_hash],
    ]);
    if (p?.decision === "deny" && reasons[p.reason_code])
      pb.insertBefore(
        element("p", "policy-callout", reasons[p.reason_code]),
        pb.querySelector("dl"),
      );
    body.append(pb);
  }
  body.append(linksBlock(sel.kind, links));
  const details = element("details", "detail-json");
  details.open = Boolean(preserveJson);
  details.append(
    element("summary", "", "查看事件 JSON"),
    element("pre", "", JSON.stringify(e, null, 2)),
  );
  body.append(details);
}
async function refresh() {
  if (state.loading) return;
  state.loading = true;
  $("refresh").disabled = true;
  try {
    const response = await fetch("/api/audit", { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    if (
      !["sources", "commands", "tools", "issues"].every((k) =>
        Array.isArray(data[k]),
      )
    )
      throw new Error("日志响应格式异常");
    state.data = data;
    $("error").hidden = true;
    render();
    state.loaded = true;
    const t = formatTime(data.updated_at || new Date().toISOString());
    $("last-updated").textContent = "最近读取 " + t.date + " " + t.time;
  } catch (err) {
    $("error").hidden = false;
    $("error").textContent =
      "读取本地审计服务失败。" +
      err.message +
      (state.loaded ? "，页面保留上次读取结果。" : "，请确认服务正在运行。");
    if (!state.loaded) {
      $("last-updated").textContent = "等待读取日志";
      $("showing").textContent = "尚未读取";
    }
  } finally {
    state.loading = false;
    $("refresh").disabled = false;
  }
}
function resetFilters() {
  state.groupDetail = null;
  state.page = 1;
  state.search = "";
  state.result = "";
  state.decision = "";
  $("search").value = "";
  $("result-filter").value = "";
  $("policy-filter").value = "";
}
function startViewer() {
  $("group-calls").checked = state.grouped;
  $("group-calls").addEventListener("change", () => {
    state.grouped = $("group-calls").checked;
    state.groupDetail = null;
    state.page = 1;
    render();
  });
  $("back-to-groups").addEventListener("click", () => {
    const { key, returnPage } = state.groupDetail;
    state.groupDetail = null;
    state.page = returnPage;
    render();
    Array.from($("rows").querySelectorAll("[data-group-key]"))
      .find((button) => button.dataset.groupKey === key)?.focus();
  });
  document.querySelectorAll("[data-view]").forEach((button) =>
    button.addEventListener("click", () => {
      if (state.view === button.dataset.view) return;
      state.view = button.dataset.view;
      resetFilters();
      render();
    }),
  );
  $("clear").addEventListener("click", () => {
    resetFilters();
    render();
  });
  for (const [id, prop, event] of [
    ["search", "search", "input"],
    ["result-filter", "result", "change"],
    ["policy-filter", "decision", "change"],
    ["sources", "source", "change"],
  ]) {
    $(id).addEventListener(event, () => {
      state.groupDetail = null;
      state[prop] = $(id).value;
      state.page = 1;
      render();
    });
  }
  $("prev").addEventListener("click", () => {
    state.page--;
    render();
  });
  $("next").addEventListener("click", () => {
    state.page++;
    render();
  });
  $("close").addEventListener("click", () => $("drawer").close());
  $("drawer").addEventListener("close", () => {
    state.selection = null;
    lastDrawerKey = "";
  });
  $("drawer").addEventListener("click", (event) => {
    if (event.target === $("drawer")) $("drawer").close();
  });
  document.addEventListener("keydown", (event) => {
    if (
      event.key === "/" &&
      !event.ctrlKey &&
      !event.metaKey &&
      !event.altKey &&
      !$("drawer").open &&
      !["INPUT", "SELECT", "TEXTAREA"].includes(document.activeElement.tagName)
    ) {
      event.preventDefault();
      $("search").focus();
    }
  });
  $("refresh").addEventListener("click", refresh);
  $("auto").addEventListener("change", () => {
    if ($("auto").checked) refresh();
  });
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && $("auto").checked) refresh();
  });
  setInterval(() => {
    if (!document.hidden && $("auto").checked) refresh();
  }, 5000);
  refresh();
}

if (typeof document !== "undefined") startViewer();
if (typeof module !== "undefined" && module.exports)
  module.exports = { callGroupKey, groupCalls };
