## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

Rules:
- When graphify-out/graph.json exists, run `graphify query "<question>"` before your first grep, search or source-file read for a codebase question, and put this rule in every subagent prompt that explores code. Read raw files only for lines the graph or an earlier read already located. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- Dirty graphify-out/ files are expected after hooks or incremental updates; dirty graph files are not a reason to skip graphify. Only skip graphify if the task is about stale or incorrect graph output, or the user explicitly says not to use it.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
- A committed graphify-out/graph.json is rewritten whole on every build, so a large diff to it in a pull request is expected. Do not flag it as churn or suggest skipping the graph rebuild or its hooks.

## Memory architecture (three-tier)

Persistent memory is local and deterministic. Read before searching, write before ending.

| Tier | Path | Purpose |
|---|---|---|
| 1 — Global host constraints | `~/.config/opencode/memory/human.md` | Immutable Windows 11 host / WSL2 boundary, non-interactive rules, network isolation, disk hygiene. Never contradict it. |
| 2 — Codebase atlas | `.opencode/atlas/` | `system-architecture.md`, `module-routing.md`, `interface-lifecycles.md`, `failure-modes.md`. Static lookup maps. |

Rules:
- **Orientation first**: at session start, read Tier 1 and the Tier 2 file relevant to the task before any broad grep/search or source-file read (graphify query still applies per the rules above; the atlas tells you where to look before you query).
- **Prefer the atlas over discovery**: if the answer is in `.opencode/atlas/`, do not re-derive it with token-heavy search.
- **Keep the atlas truthful**: if you change architecture, module responsibilities, lifecycle ordering, or discover a new gotcha, update the matching atlas file in the same session.

## Episodic memory (Tier 3)

Path: `.opencode/memory/` — `test-baseline.md`, `operational-state.md`, `session-handoff.md`.

Rules:
- Never assume operational success: verify against `test-baseline.md` (run pytest, compare counts), process checks, or SHA-256 validation, and record the result.
- **Handoff duty**: at the end of every working session, append a dated entry to `.opencode/memory/session-handoff.md` (Did / Verified / In flight / Next) and refresh `.opencode/memory/operational-state.md`.
- Update `test-baseline.md`'s run log with every full pytest run; keep the collected count current.

## Mandatory Local Memory Protocol (every session + after `/compact`)

Non-negotiable, self-sustaining, and applies to every session — including immediately after a `/compact` (which drops memory files from context).

- **Turn-1 Load**: before any code edit, command execution, or VM operation, read `.opencode/memory/operational-state.md`, `.opencode/memory/session-handoff.md`, and `.opencode/memory/test-baseline.md`. Re-read all three immediately after `/compact`.
- **Pre-Action Checkpoint**: before executing any network-altering operation, TUN toggle, Hyper-V VM action (start / stop / save / restore / deploy / checkpoint), or candidate build, append a timestamped in-flight note to `.opencode/memory/session-handoff.md` (what is about to run + expected outcome) so progress survives an unexpected disconnect.
- **Pre-Exit Gate**: do not conclude any session until all of the following hold:
  - `operational-state.md`, `session-handoff.md`, and `test-baseline.md` reflect current `HEAD`, test counts, and open items;
  - `.venv/bin/python -m graphify update .` has run if any code was edited;
  - all memory updates are committed via `git-atomic` (one logical unit, Conventional Commit message).

## Failure-mode guardrails (PerchVPN, mandatory)

- **No unscoped refactoring**: change only the exact lines the task requires; never rewrite adjacent helpers, add speculative defensive wrappers, or alter public interfaces unless explicitly requested.
- **Verification gate**: never declare a fix complete from static inspection alone. Run targeted pytest suites — full suite plus `build-candidate.ps1` + SHA-256 verification when build/runtime paths change — and report concrete exit codes/output as evidence.
- **Evidence-first triage (`investigate` before `build`)**: prove root cause from logs, call graphs (`graphify` / `codebase-memory-mcp`), or read-only probes before editing async locks, NDIS/Wintun timing, or sing-box configs. No speculative fixes.
- **Cross-layer discipline (Windows OS / NDIS / asyncio / sing-box)**:
  - Never block the asyncio event loop with synchronous PowerShell/CIM calls or DNS lookups.
  - Never blanket-kill processes (`Stop-Process -Name sing-box`, `taskkill /IM sing-box.exe`); never touch non-`PerchVPN` Wintun adapters/routes — disconnecting the host's active tunnel severs the session too.
  - Account for PyInstaller frozen-bundle rules (`sys._MEIPASS`, hidden imports, `--windowed` silent-exit traps).
- **Context efficiency**: query `graphify` / `codebase-memory-mcp` before reading large files; trim logs/outputs to relevant lines.

## Workflow skill routing

Route work to the matching workflow skill (available via the `skill` tool) instead of improvising:

| Situation | Skill |
|---|---|
| Runtime crash, adapter timeout, unexpected error, or reproducing a failure | `investigate` |
| Pre-commit / pre-build audit, schema check, or verifying a fix actually works | `verify` |
| Architecture planning or a structural refactor with unresolved requirements | `grill-me` |
| Library/API fact-finding, version checks, or external behaviour lookup | `research` |

Rules:
- Load the routed skill before starting the work it covers; follow its operating rules end to end.
- Before any recursive (multi-hop, file-tree-wide, or repeated grep) search pass, reference `graphify-out/GRAPH_REPORT.md` first and prefer `graphify query`/`path`/`explain` for scoped subgraphs.
- Do not begin implementation while a routed skill indicates critical requirements remain unresolved.
