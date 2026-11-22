# Contributing to pcapreplay

Thanks for your interest. This project is small, dependency-free and meant to stay easy to read, so a few ground rules
keep it that way.

## Ground rules

* **Standard library only.** No third-party modules and no cgo. If you think a dependency is unavoidable, open an issue
  first.
* **Windows and Linux both matter.** Platform code lives behind build tags or `_windows.go` / `_linux.go` / `_other.go`
  files. Before sending a pull request make sure both `GOOS=windows` and `GOOS=linux` build.
* **Captures are hostile input.** Validate every length and offset taken from packet or file bytes before using it.
* **Keep hot paths allocation-free.** The reader, decoder, filter and rewrite loop are benchmarked and measured; do not
  add per-packet allocations or per-packet logging that is not guarded by `Logger.Enabled`.
* **Explicit over implicit.** The transport mode is never guessed; nothing is sent that the user did not select.

## Getting started

```bash
git clone https://github.com/AlexRudyak/pcapreplay.git
cd pcapreplay
go build ./...
go test ./...
go run ./cmd/pcapreplay gui          # try the interface
```

Read the top-level [README](README.md) for the big picture, [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design,
and the `README.md` inside the package you are changing (every package under `internal/` and `cmd/` has one).

## Before you open a pull request

```bash
gofmt -l .                                   # must print nothing
go vet ./...
go test -count=1 ./...
GOOS=linux   go build ./... 
GOOS=windows go build ./...
```

* Add or update tests for the behaviour you changed. The TCP engine has an in-process fake server
  (`internal/replay/tcp_test.go`), the GUI tests drive the real handler with `httptest`, and Linux end-to-end scripts
  live in [`scripts/`](scripts/README.md).
* Update the docs that describe the behaviour: the package README, [README-CLI.md](README-CLI.md) for flags,
  and the main README when a feature appears or changes.
* Document exported identifiers and non-trivial functions with a doc comment that starts with the name.
* Keep changes focused. A bug fix and a refactor belong in separate pull requests.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`, for example

```
feat(replay): honour the peer's window when sending bursts
fix(gui): show the source before the destination in the conversation editor
docs: add a full command-line reference
```

Types used here: `feat`, `fix`, `perf`, `refactor`, `test`, `docs`, `build`, `ci`, `chore`. The scope is usually a package
name (`replay`, `gui`, `backend`, `cli`, ...). Explain *why* in the body when it is not obvious.

## Testing the network paths

Unit tests never touch the network. The Linux backend and the TCP engine are verified end to end by
`scripts/e2e-udp.sh` and `scripts/e2e-tcp.sh` (root, `iproute2`, `python3`, nftables or iptables). The Windows WinDivert
path needs the driver and an elevated prompt; if you can test it on real hardware, please say so in your pull request,
because that is the least-verified part of the project.

## Reporting bugs

Use the issue templates. Re-run the failing command with `-vv` (or `-vvv -count 20`) and include the log, after
removing private addresses. Please do not attach captures containing sensitive traffic. For security problems see
[SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contributions are licensed under the [MIT License](LICENSE).
