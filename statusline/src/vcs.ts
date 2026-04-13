/**
 * VCS status detection for git and jj.
 *
 * jj is preferred over git: jj repos colocate a .git directory but
 * not vice versa.
 *
 * Repo kind and binary availability are cached. Status fetched lazily
 * on first request and refetched only after invalidateVcs().
 */

import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join } from "node:path";
import type { VcsKind, VcsStatus } from "./types.js";

const binAvailable: Partial<Record<VcsKind, boolean>> = {};

function hasBinary(name: VcsKind): boolean {
	const cached = binAvailable[name];
	if (cached !== undefined) return cached;
	const r = spawnSync(name, ["--version"], { stdio: "ignore" });
	const ok = !r.error || (r.error as NodeJS.ErrnoException).code !== "ENOENT";
	binAvailable[name] = ok;
	return ok;
}

const kindByCwd = new Map<string, VcsKind | null>();

function detectKind(cwd: string): VcsKind | null {
	if (kindByCwd.has(cwd)) return kindByCwd.get(cwd)!;
	let kind: VcsKind | null = null;
	// Walk up to find a repo root. jj repos colocate .git so check .jj first.
	let dir = cwd;
	while (true) {
		if (existsSync(join(dir, ".jj")) && hasBinary("jj")) {
			kind = "jj";
			break;
		}
		if (existsSync(join(dir, ".git")) && hasBinary("git")) {
			kind = "git";
			break;
		}
		const parent = dirname(dir);
		if (parent === dir) break;
		dir = parent;
	}
	kindByCwd.set(cwd, kind);
	return kind;
}

let cachedStatus: VcsStatus | null = null;
let inflight = false;
let seq = 0;
let onUpdate: (() => void) | null = null;

export function setVcsUpdateCallback(cb: (() => void) | null): void {
	onUpdate = cb;
}

export function invalidateVcs(): void {
	cachedStatus = null;
	seq++;
}

function run(cmd: string, args: string[], timeoutMs = 300): Promise<string | null> {
	return new Promise((resolve) => {
		let stdout = "";
		let resolved = false;
		const finish = (r: string | null) => {
			if (resolved) return;
			resolved = true;
			clearTimeout(timer);
			resolve(r);
		};
		// detached: the child leads its own process group, so the timeout below
		// can signal the entire tree. Without it we can only reach the direct
		// child, and any grandchild it is blocked on survives us.
		const proc = spawn(cmd, args, { stdio: ["ignore", "pipe", "ignore"], detached: true });
		proc.stdout.on("data", (d) => (stdout += d.toString()));
		proc.on("close", (code) => finish(code === 0 ? stdout.trim() : null));
		proc.on("error", () => finish(null));
		const signalGroup = (sig: NodeJS.Signals) => {
			const pid = proc.pid;
			try {
				if (pid === undefined) throw new Error("no pid");
				// Negative pid targets the group. Safe because `detached` made the
				// child its own group leader (pgid === pid), so this can never
				// reach our own group.
				process.kill(-pid, sig);
			} catch {
				try {
					proc.kill(sig);
				} catch {
					// Already gone.
				}
			}
		};
		const timer = setTimeout(() => {
			// Signal the group, not just the direct child. jj shells out to gpg to
			// sign commits; signalling only jj leaves a blocked gpg orphaned and
			// reparented to init, where it holds a gpg-agent connection forever.
			// At one leak per render that exhausts the agent's accept backlog, and
			// every subsequent gpg client -- including the shell startup hook --
			// then blocks in connect().
			//
			// SIGTERM before SIGKILL: git may be mid-write on .git/index here, and
			// SIGKILL would strand an index.lock that breaks later git commands.
			// A wedged gpg dies on SIGTERM perfectly well -- the original bug was
			// never that it ignored the signal, only that it never received one.
			signalGroup("SIGTERM");
			const escalate = setTimeout(() => {
				// Re-check liveness: without this we could signal a recycled pid.
				if (proc.exitCode === null && proc.signalCode === null) signalGroup("SIGKILL");
			}, 200);
			// Never let the escalation hold the event loop open.
			escalate.unref?.();
			finish(null);
		}, timeoutMs);
	});
}

// ── jj ───────────────────────────────────────────────────────────────────

async function fetchJj(): Promise<VcsStatus | null> {
	// --ignore-working-copy keeps this read-only. Without it, every render
	// snapshots the working copy, which rewrites the working-copy commit --
	// and under signing.behavior="own" a rewrite means a GPG signature, so a
	// statusline refresh becomes a YubiKey touch (or an indefinite hang when
	// the key is absent). Upstream jj recommends the flag for exactly this
	// case. Cost: counts reflect the last real jj operation and can lag until
	// the next jj command -- acceptable, because a status display must never
	// mutate the repo it is reporting on.
	const logLine = await run("jj", [
		"log",
		"--ignore-working-copy",
		"--no-graph",
		"--limit",
		"1",
		"-T",
		'change_id.shortest() ++ "\\x00" ++ bookmarks.join(",") ++ "\\x00" ++ description.first_line()',
	]);
	if (logLine === null) return null;

	const [changeId, bookmarksStr, _desc] = logLine.split("\0");
	const bookmarks = (bookmarksStr ?? "").split(",").filter(Boolean);
	const head = bookmarks[0] ?? changeId ?? null;

	const status = await run("jj", ["diff", "--ignore-working-copy", "--summary"], 500);
	let modified = 0;
	let added = 0;
	let removed = 0;
	if (status) {
		for (const line of status.split("\n")) {
			if (!line) continue;
			const code = line[0];
			if (code === "M") modified++;
			else if (code === "A" || code === "C") added++;
			else if (code === "D") removed++;
		}
	}

	return { kind: "jj", head, modified, added, removed };
}

// ── git ──────────────────────────────────────────────────────────────────

async function fetchGit(): Promise<VcsStatus | null> {
	const branch = await run("git", ["branch", "--show-current"]);
	if (branch === null) return null;

	let head = branch;
	if (!head) {
		const sha = await run("git", ["rev-parse", "--short", "HEAD"]);
		head = sha ? `${sha} (detached)` : "detached";
	}

	const porcelain = await run("git", ["status", "--porcelain"], 500);
	let modified = 0;
	let added = 0;
	let removed = 0;
	if (porcelain) {
		for (const line of porcelain.split("\n")) {
			if (!line) continue;
			const x = line[0];
			const y = line[1];
			if (x === "?" && y === "?") {
				added++;
				continue;
			}
			if (x === "D" || y === "D") removed++;
			else if (x === "A") added++;
			else if (x !== " " || y !== " ") modified++;
		}
	}

	return { kind: "git", head, modified, added, removed };
}

async function fetchVcsStatus(cwd: string): Promise<VcsStatus | null> {
	const kind = detectKind(cwd);
	if (!kind) return null;
	return kind === "jj" ? fetchJj() : fetchGit();
}

/**
 * Get cached VCS status. Triggers a fetch only on first call or after
 * invalidateVcs(). Renders never block — they read whatever is cached.
 */
export function getVcsStatus(cwd: string): VcsStatus | null {
	if (detectKind(cwd) === null) return null;
	if (cachedStatus === null && !inflight) {
		inflight = true;
		const mySeq = seq;
		void fetchVcsStatus(cwd).then((result) => {
			inflight = false;
			if (mySeq !== seq) return;
			cachedStatus = result;
			onUpdate?.();
		});
	}
	return cachedStatus;
}
