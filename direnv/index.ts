/**
 * Direnv Extension
 *
 * Loads direnv environment variables on session start, then watches the
 * files direnv itself tracks (.envrc, watch_file entries, direnv allow
 * state, ...) and reloads only when one of them changes.
 *
 * The watch list is decoded from DIRENV_WATCHES with `direnv show_dump`,
 * so it always matches direnv's own invalidation rules. Watching
 * .direnv/ instead would feed back into itself: a stale-cache
 * `direnv export` (nix-direnv) rewrites .direnv/, re-triggering the
 * watcher while the previous export is still running. Combined with a
 * slow nix eval this spawns unbounded concurrent evals.
 *
 * The bash tool spawns a new process per command (no persistent shell),
 * so the working directory never changes between bash calls. Running
 * direnv after every bash command is therefore unnecessary — file
 * watching is both cheaper and more correct.
 *
 * Requirements:
 *   - direnv installed and in PATH
 *   - .envrc must be allowed (run `direnv allow` in your shell first)
 */

import { exec, execFile } from "node:child_process";
import { type FSWatcher, watch } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@mariozechner/pi-coding-agent";

/** Debounce before reloading after a file-system event (ms). */
const RELOAD_DEBOUNCE_MS = 300;

type Status = "on" | "blocked" | "error" | "off";

export default function (pi: ExtensionAPI) {
	let watchers: FSWatcher[] = [];
	let reloadTimer: ReturnType<typeof setTimeout> | null = null;
	let latestCtx: ExtensionContext | null = null;
	// A stale nix-direnv cache turns `direnv export` into a full nix
	// eval that can run for minutes. Never run more than one export at
	// a time; coalesce triggers that arrive meanwhile into a single
	// re-run once the current one finishes.
	let exportRunning = false;
	let exportPending = false;

	function updateStatus(ctx: ExtensionContext, status: Status): void {
		if (!ctx.hasUI) return;
		if (status === "on" || status === "off") {
			ctx.ui.setStatus("direnv", undefined);
			return;
		}
		const text =
			status === "blocked"
				? ctx.ui.theme.fg("warning", "direnv:blocked")
				: ctx.ui.theme.fg("error", "direnv:error");
		ctx.ui.setStatus("direnv", text);
	}

	function loadDirenv(cwd: string, ctx: ExtensionContext): void {
		if (exportRunning) {
			exportPending = true;
			return;
		}
		exportRunning = true;
		exec("direnv export json", { cwd }, (error, stdout, stderr) => {
			exportRunning = false;
			// The session may have shut down while the export ran; don't
			// touch the UI or re-arm watchers after stopWatchers() already
			// cleaned up — they would leak until process exit.
			if (!latestCtx) return;
			if (error) {
				const message = (stderr || error.message).toLowerCase();
				updateStatus(ctx, /allow|blocked|denied|not allowed/.test(message) ? "blocked" : "error");
			} else if (!stdout.trim()) {
				updateStatus(ctx, "off");
			} else {
				try {
					const env = JSON.parse(stdout) as Record<string, string | null>;
					let loadedCount = 0;
					for (const [key, value] of Object.entries(env)) {
						if (value === null) {
							delete process.env[key];
						} else {
							process.env[key] = value;
							loadedCount++;
						}
					}
					updateStatus(ctx, loadedCount > 0 ? "on" : "off");
				} catch {
					updateStatus(ctx, "error");
				}
			}
			// The export may have changed DIRENV_WATCHES; re-arm from it.
			startWatchers(cwd);
			if (exportPending) {
				exportPending = false;
				scheduleReload();
			}
		});
	}

	function scheduleReload(): void {
		if (!latestCtx) return;
		if (reloadTimer) clearTimeout(reloadTimer);
		reloadTimer = setTimeout(() => {
			reloadTimer = null;
			if (!latestCtx) return;
			// Watchers are re-armed when the export finishes.
			loadDirenv(latestCtx.cwd, latestCtx);
		}, RELOAD_DEBOUNCE_MS);
	}

	function armWatcher(path: string): void {
		try {
			const w = watch(path, () => scheduleReload());
			// FSWatcher emits "error" asynchronously, e.g. when a watched
			// entry vanishes mid-event. Without a listener that becomes an
			// uncaughtException and takes down the whole agent. Close the
			// dead watcher and schedule a reload, which also re-arms the
			// watchers.
			w.on("error", () => {
				try {
					w.close();
				} catch {
					/* ignore */
				}
				scheduleReload();
			});
			watchers.push(w);
		} catch {
			// path may not exist (yet) — that's fine
		}
	}

	/**
	 * Resolve the paths direnv itself watches for invalidation (.envrc,
	 * allow/deny state, watch_file entries, ...). Falls back to .envrc
	 * when DIRENV_WATCHES is not loaded yet or cannot be decoded.
	 */
	function watchedPaths(cwd: string, cb: (paths: string[]) => void): void {
		const dump = process.env.DIRENV_WATCHES;
		if (!dump) {
			cb([join(cwd, ".envrc")]);
			return;
		}
		execFile("direnv", ["show_dump", dump], (error, stdout) => {
			try {
				if (error) throw error;
				const entries = JSON.parse(stdout) as { path: string }[];
				cb(entries.map((e) => e.path));
			} catch {
				cb([join(cwd, ".envrc")]);
			}
		});
	}

	function startWatchers(cwd: string): void {
		watchedPaths(cwd, (paths) => {
			stopWatchers();
			for (const path of paths) {
				armWatcher(path);
			}
		});
	}

	function stopWatchers(): void {
		for (const w of watchers) {
			try {
				w.close();
			} catch {
				/* ignore */
			}
		}
		watchers = [];
	}

	pi.on("session_start", async (_event, ctx) => {
		latestCtx = ctx;
		// Watchers are armed when the export finishes, from the
		// DIRENV_WATCHES it produces.
		loadDirenv(ctx.cwd, ctx);
	});

	pi.on("session_shutdown", async () => {
		stopWatchers();
		if (reloadTimer) {
			clearTimeout(reloadTimer);
			reloadTimer = null;
		}
		exportPending = false;
		latestCtx = null;
	});

	pi.registerCommand("direnv", {
		description: "Reload direnv environment variables",
		handler: async (_args, ctx) => {
			latestCtx = ctx;
			loadDirenv(ctx.cwd, ctx);
			if (ctx.hasUI) ctx.ui.notify("direnv reloaded", "info");
		},
	});
}
