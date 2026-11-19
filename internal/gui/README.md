# internal/gui

The local **web interface**: an HTTP server (standard library only) with a job manager and an embedded static frontend.
Started by `pktreplay gui`.

```go
srv, _ := gui.NewWithOptions("127.0.0.1:0", version, gui.Options{DataDir: dir})
fmt.Println(srv.URL())     // http://127.0.0.1:PORT/?t=TOKEN
srv.Serve()
```

`New(addr, version)` is the same without history. The frontend is embedded with `go:embed web/*` (`web/index.html`,
`style.css`, `app.js`): no build step, works offline, no inline scripts (strict CSP).

## Security model (`server.go: guard`)

* **Loopback only**: any other listen address is refused.
* A random **per-launch token**: the first visit to `/?t=TOKEN` is exchanged for an `HttpOnly`, `SameSite=Strict`
  cookie and the token is removed from the address bar. Everything else needs the cookie (constant-time compare).
* **Host allow-list** (`127.0.0.1:port`, `localhost:port`, `[::1]:port`) defeats DNS rebinding.
* State-changing requests must carry a same-origin `Origin` (when present) and `Content-Type: application/json`, so
  other web pages cannot drive the tool; request bodies are limited to 1 MiB.
* Security headers: `Content-Security-Policy`, `X-Content-Type-Options`, `Cache-Control: no-store`.
* On a successful token exchange the response carries `X-Pktreplay: gui`, which lets a second launch recognise a live
  instance (see `cmd/pktreplay`).

## Job manager (`jobs.go`)

One job at a time (analysis or replay). The UI starts a job with `POST` and **polls** `/api/status`, which returns
progress counters, the technical log and the final result. `StartReplay` writes the history run *first*, registers the
pcap in the background, optionally tees a packet copy, and finalises the run (`done` / `failed` / `cancelled`) through
`finishRun`. Stop is reported as cancelled, not as an error.

## HTTP API

| Route | Purpose |
|---|---|
| `GET /api/info` | Version, OS/arch, elevation, home and working directories, browse roots, bundled sample captures. |
| `GET /api/fs` | Browse the file system for the open dialog. |
| `POST /api/filter/check` | Validate a filter expression. |
| `POST /api/stats` | Start the analysis job (summary + conversations). |
| `POST /api/replay` | Validate a `ReplayRequest` and start the replay job. |
| `POST /api/cancel`, `GET /api/status` | Stop / observe the current job. |
| `POST /api/elevate` | Windows: relaunch as administrator (UAC). |
| `GET /api/history`, `GET\|POST /api/history/settings`, `GET /api/history/export`, `POST /api/history/clear` | History list, settings, export, clear. |
| `GET /api/history/{id}` + `/update`, `/delete`, `/packets`, `/preview` | One run: details, edit, delete, packet copy download and preview. |
| `GET /api/library`, `POST /api/library/add`, `GET /api/library/{id}` + `/update`, `/delete`, `/remove-copy`, `/download` | The pcap library. |

`ReplayRequest` (`request.go`) mirrors the CLI flags as JSON; `ConvRuleRequest` is one per-conversation edit
converted into a `conv.Rule`.

## Platform helpers

`IsElevated()` and the elevation relaunch live in `admin_*.go` / `elevate_*.go` (Windows token check and `ShellExecute`
with `runas`; stubs elsewhere).

## Frontend (`web/`)

A flow rather than tabs: welcome (open or recent files) → analysing (progress) → **1. Choose conversations** with the
send panel **2. Send** always visible → run/result view. History and Settings are separate pages with the pcap library
as a tab. Light and dark themes follow the system. Per-conversation editor shows Source on the left and Destination on
the right, with a live "will be sent as" preview.

## Tests

`gui_test.go`, `gui_history_test.go`, `gui_library_test.go` drive the real handler (`httptest`): auth and origin
guards, jobs, validation, history and library lifecycles.

Uses: `replay`, `stats`, `history`, `record`, `conv`, `backend`, `filter`, `pace`, `mutate`, `pcapio`.
