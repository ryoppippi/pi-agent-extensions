/**
 * permission-gate — confirm or block dangerous bash commands before they run.
 *
 * Rules match either the raw command string (regex) or tokenized pipelines
 * of argv arrays (see shell.ts), and choose an action:
 *   - "prompt": show Yes/No with a free-text rejection reason (fed back to
 *     the model). Toggle with /gate or PI_NO_GATE=1.
 *   - "block":  reject outright with a fixed reason. Stays active when
 *     /gate turns prompting off; disable via `disabledRules` or PI_NO_GATE=1.
 *
 * Config (merge order, later layers may disable earlier ones by label):
 *   built-ins
 *   ~/.config/pi-agent-extensions/permission-gate/rules.{ts,mjs,js}  (user code, optional)
 *   ~/.config/pi-agent-extensions/permission-gate/rules.json         (user JSON — /gate add|rm write here)
 *   <cwd>/.pi/permission-gate.json                                   (project JSON only)
 *
 * Based on pi's built-in permission-gate example, PR #13, and the
 * block-commands extension by Mic92 (github.com/Mic92/dotfiles).
 */

import type { ExtensionAPI, ExtensionContext, BashToolCallEvent } from "@mariozechner/pi-coding-agent";
import type { ArgvPipeline, CompiledRule, GateHelpers, WarnFn } from "./types.ts";
import { searchPaths } from "./builtin-rules.ts";
import { pipelines, simpleCommands } from "./shell.ts";
import { compileRules, type ConfigLayers, loadConfig, saveUserJson } from "./config.ts";
import { showReviewPrompt } from "./ui.ts";

const GATE_SUBCMDS = "list(ls)|add|remove(rm)|reload";
const HELPERS: GateHelpers = { simpleCommands, pipelines, searchPaths };

// ── matching ─────────────────────────────────────────────────────────────

/** Pipelines as argv lists, recursing into command/process substitutions. */
function collectPipelines(script: string): ArgvPipeline[] {
	return pipelines(script).flatMap((p) => [
		p.map((c) => c.argv).filter((argv) => argv.length),
		...p.flatMap((c) => c.subs.flatMap(collectPipelines)),
	]).filter((p) => p.length);
}

function matchRules(command: string, rules: CompiledRule[]): CompiledRule[] {
	let argvPipes: ArgvPipeline[] | undefined;
	return rules.filter((r) =>
		r.kind === "regex"
			? r.pattern.test(command)
			: (argvPipes ??= collectPipelines(command)).some((p) => r.test(p)),
	);
}

// ── extension ────────────────────────────────────────────────────────────

export default function permissionGate(pi: ExtensionAPI) {
	// PI_NO_GATE disables the extension entirely (prompts and block rules).
	if (process.env.PI_NO_GATE) return;

	let promptsEnabled = true;
	let layers: ConfigLayers = { userCode: {}, userJson: {}, project: {} };
	let rules: CompiledRule[] = compileRules(layers);

	function updateStatus(ctx: ExtensionContext): void {
		if (!ctx.hasUI) return;
		ctx.ui.setStatus("gate", ctx.ui.theme.fg("dim", promptsEnabled ? "\uf132 gate" : "\uf132 block"));
	}

	async function reloadRules(cwd: string, warn?: WarnFn): Promise<void> {
		layers = await loadConfig(cwd, HELPERS, warn);
		rules = compileRules(layers, warn);
	}

	// ── events ───────────────────────────────────────────────────────────

	pi.on("session_start", async (_event, ctx) => {
		const warn: WarnFn = (msg) => ctx.hasUI ? ctx.ui.notify(msg, "warning") : undefined;
		await reloadRules(ctx.cwd, warn);
		updateStatus(ctx);
	});

	pi.on("tool_call", async (event, ctx) => {
		if (event.toolName !== "bash") return undefined;
		const command = (event as BashToolCallEvent).input.command;
		if (!command) return undefined;

		const matched = matchRules(command, rules);
		if (matched.length === 0) return undefined;

		// Block wins over prompt and ignores the /gate toggle.
		const block = matched.find((r) => r.action === "block");
		if (block) {
			return { block: true, reason: block.reason ?? `Blocked (${block.label})` };
		}

		const prompts = matched.filter((r) => r.action === "prompt");
		if (!promptsEnabled || prompts.length === 0) return undefined;

		const labels = prompts.map((m) => m.label).join(", ");
		if (!ctx.hasUI) {
			return { block: true, reason: `Dangerous command blocked (${labels}) — no UI` };
		}

		pi.events.emit("permission-gate:waiting", { command, labels });
		const result = await showReviewPrompt(ctx, command, labels, pi.events);
		pi.events.emit("permission-gate:resolved");

		return result.allow ? undefined : { block: true, reason: result.reason };
	});

	// ── /gate ────────────────────────────────────────────────────────────

	pi.registerCommand("gate", {
		description: `Permission gate — toggle prompts or manage rules: /gate [${GATE_SUBCMDS}]`,
		handler: async (args, ctx) => {
			const sub = args?.trim().toLowerCase() ?? "";
			const warn: WarnFn = (msg) => ctx.ui.notify(msg, "warning");

			// Toggle prompting (block rules unaffected).
			if (!sub) {
				promptsEnabled = !promptsEnabled;
				updateStatus(ctx);
				ctx.ui.notify(
					promptsEnabled
						? "Permission gate: prompts enabled"
						: "Permission gate: prompts disabled (block rules still active)",
					"info",
				);
				return;
			}

			if (sub === "list" || sub === "ls") {
				const groups: Record<string, string[]> = {};
				for (const r of rules) {
					const tag = r.action === "block" ? "[block] " : "";
					(groups[r.source] ??= []).push(`${tag}${r.label}`);
				}
				const sections = Object.entries(groups).map(([source, labels]) => {
					const heading = source.charAt(0).toUpperCase() + source.slice(1);
					return `${heading} (${labels.length}):\n${labels.map((l) => `  • ${l}`).join("\n")}`;
				});
				ctx.ui.notify(sections.join("\n\n") || "No active rules", "info");
				return;
			}

			if (sub === "reload") {
				await reloadRules(ctx.cwd, warn);
				const src = layers.userCodePath ? ` from ${layers.userCodePath}` : "";
				ctx.ui.notify(`Reloaded ${rules.length} rule(s)${src}`, "info");
				return;
			}

			// Add regex rule → user JSON.
			if (sub === "add") {
				const pattern = await ctx.ui.input("Pattern", "Regex (e.g. \\\\bdocker\\\\s+rm\\\\b)");
				if (!pattern) return;
				const label = await ctx.ui.input("Label", "Short name (e.g. docker remove)");
				if (!label) return;
				try { new RegExp(pattern, "i"); } catch {
					ctx.ui.notify("Invalid regex", "error");
					return;
				}
				const action = (await ctx.ui.select("Action", ["prompt", "block"])) as "prompt" | "block" | undefined;
				if (!action) return;
				const reason = action === "block"
					? await ctx.ui.input("Reason (sent to model)", "")
					: undefined;
				const cfg = layers.userJson;
				cfg.extraRules = [...(cfg.extraRules ?? []), { pattern, label, action, ...(reason ? { reason } : {}) }];
				saveUserJson(cfg);
				await reloadRules(ctx.cwd, warn);
				ctx.ui.notify(`Rule added: ${label}`, "info");
				return;
			}

			// Remove: user-json rules are spliced; anything else is disabled by label.
			if (sub === "remove" || sub === "rm") {
				if (rules.length === 0) { ctx.ui.notify("No rules to remove", "info"); return; }
				const choice = await ctx.ui.select("Remove rule", rules.map((r) => r.label));
				if (!choice) return;

				const cfg = layers.userJson;
				const target = rules.find((r) => r.label === choice);
				const idx = (cfg.extraRules ?? []).findIndex((r) => r.label === choice);
				if (target?.source === "user-json" && idx >= 0) {
					cfg.extraRules!.splice(idx, 1);
				} else {
					cfg.disabledRules = [...new Set([...(cfg.disabledRules ?? []), choice])];
				}
				saveUserJson(cfg);
				await reloadRules(ctx.cwd, warn);
				ctx.ui.notify(`Rule removed: ${choice}`, "info");
				return;
			}

			ctx.ui.notify(`Usage: /gate [${GATE_SUBCMDS}]`, "info");
		},
	});
}
