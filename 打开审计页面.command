#!/bin/zsh
set -eu
cd -- "${0:A:h}"

url=http://127.0.0.1:18765
viewer_ready() {
  /usr/bin/curl --noproxy '*' -fsS --max-time 1 -D - -o /dev/null "$url/index.html" 2>/dev/null |
    /usr/bin/grep -Eiq '^X-DWS-Audit-Viewer: 1[[:space:]]*$'
}

if viewer_ready; then
  /usr/bin/open "$url/"
  exit 0
fi

export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
python3 server.py --port 18765 &
viewer_pid=$!
trap 'kill "$viewer_pid" 2>/dev/null || true' EXIT
for attempt in {1..50}; do
  if ! kill -0 "$viewer_pid" 2>/dev/null; then
    wait "$viewer_pid"
    exit 1
  fi
  if viewer_ready; then
    /usr/bin/open "$url/"
    print '按 Ctrl+C 可关闭本次启动的审计页面服务。'
    wait "$viewer_pid"
    exit 0
  fi
  sleep 0.1
done
print -u2 '本机服务未能就绪，请查看上方的启动信息。'
exit 1
