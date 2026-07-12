/**
 * Direnv Extension
 *
 * Loads direnv environment variables on session start, then watches
 * .envrc and .direnv/ for changes and reloads only when needed.
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

import { exec } from "node:child_process";
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
		exec("direnv export json", { cwd }, (error, stdout, stderr) => {
			if (error) {
				const message = (stderr || error.message).toLowerCase();
				updateStatus(ctx, /allow|blocked|denied|not allowed/.test(message) ? "blocked" : "error");
				return;
			}

			if (!stdout.trim()) {
				updateStatus(ctx, "off");
				return;
			}

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
		});
	}

	function scheduleReload(): void {
		if (!latestCtx) return;
		if (reloadTimer) clearTimeout(reloadTimer);
		reloadTimer = setTimeout(() => {
			reloadTimer = null;
			if (!latestCtx) return;
			loadDirenv(latestCtx.cwd, latestCtx);
			// Re-arm watchers: one may have died with an "error" event, and
			// .envrc / .direnv may have appeared since the last arm.
			startWatchers(latestCtx.cwd);
		}, RELOAD_DEBOUNCE_MS);
	}

	function armWatcher(path: string): void {
		try {
			const w = watch(path, () => scheduleReload());
			// FSWatcher emits "error" asynchronously, e.g. when a watched
			// entry vanishes mid-event (Bun's watcher can hit ENOENT when
			// nix-direnv replaces its .direnv/flake-profile-* gc root).
			// Without a listener that becomes an uncaughtException and
			// takes down the whole agent. Close the dead watcher and
			// schedule a reload, which also re-arms the watchers.
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

	function startWatchers(cwd: string): void {
		stopWatchers();

		// Watch .envrc — covers edits and direnv allow (which rewrites .envrc state)
		armWatcher(join(cwd, ".envrc"));

		// Watch .direnv/ — covers flake rebuilds, nix develop, direnv allow state
		armWatcher(join(cwd, ".direnv"));
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
		if (reloadTimer) {
			clearTimeout(reloadTimer);
			reloadTimer = null;
		}
	}

	pi.on("session_start", async (_event, ctx) => {
		latestCtx = ctx;
		loadDirenv(ctx.cwd, ctx);
		startWatchers(ctx.cwd);
	});

	pi.on("session_shutdown", async () => {
		stopWatchers();
		latestCtx = null;
	});

	pi.registerCommand("direnv", {
		description: "Reload direnv environment variables",
		handler: async (_args, ctx) => {
			latestCtx = ctx;
			loadDirenv(ctx.cwd, ctx);
			startWatchers(ctx.cwd);
			if (ctx.hasUI) ctx.ui.notify("direnv reloaded", "info");
		},
	});
}
