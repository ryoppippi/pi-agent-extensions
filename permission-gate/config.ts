/**
 * permission-gate — config loading, compilation and persistence.
 *
 * Merge order (later layers may disable earlier ones by label):
 *   built-ins ← user rules.{ts,mjs,js} ← user rules.json ← project .pi/permission-gate.json
 *
 * rules.{ts,mjs,js} is user-scope only. A project-level .ts is refused
 * because importing it would run untrusted repo code on session_start.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { homedir } from "node:os";
import { pathToFileURL } from "node:url";
import type {
	CompiledRule,
	GateConfig,
	GateConfigModule,
	GateHelpers,
	RuleEntry,
	RuleSource,
	WarnFn,
} from "./types.ts";
import { DEFAULT_BLOCK_RULES, DEFAULT_PROMPT_RULES } from "./builtin-rules.ts";

// ── paths ────────────────────────────────────────────────────────────────

/** Resolve config directory. See .ref/config-dir.org for convention. */
export function configDir(): string {
	const override = path.join(homedir(), ".pi", "agent", "pi-agent-extensions.json");
	try {
		const cfg = JSON.parse(fs.readFileSync(override, "utf-8"));
		if (cfg.configDir) return path.join(cfg.configDir, "permission-gate");
	} catch {}
	const base = process.env.XDG_CONFIG_HOME || path.join(homedir(), ".config");
	return path.join(base, "pi-agent-extensions", "permission-gate");
}

function userCodeConfigPath(): string | undefined {
	const dir = configDir();
	for (const ext of [".ts", ".mjs", ".js"]) {
		const p = path.join(dir, `rules${ext}`);
		if (fs.existsSync(p)) return p;
	}
	return undefined;
}

function userJsonConfigPath(): string {
	return path.join(configDir(), "rules.json");
}

function projectJsonConfigPath(cwd: string): string {
	return path.join(cwd, ".pi", "permission-gate.json");
}

// ── loading ──────────────────────────────────────────────────────────────

function readJsonSafe(filePath: string, warn?: WarnFn): GateConfig {
	try {
		if (!fs.existsSync(filePath)) return {};
		return JSON.parse(fs.readFileSync(filePath, "utf-8"));
	} catch (err) {
		warn?.(`permission-gate: failed to load ${filePath}: ${(err as Error).message}`);
		return {};
	}
}

/**
 * Import rules.{ts,mjs,js}. Tries pi's bundled jiti first (handles .ts and
 * gives fresh evaluation for /gate reload); falls back to native import()
 * with a cache-busting query. Returns {} on failure with a warning.
 */
async function importCodeConfig(filePath: string, helpers: GateHelpers, warn?: WarnFn): Promise<GateConfig> {
	let mod: { default?: GateConfigModule } | undefined;
	try {
		try {
			const { createJiti } = await import("@mariozechner/jiti");
			const jiti = createJiti(import.meta.url, { moduleCache: false, fsCache: false });
			mod = await jiti.import(filePath);
		} catch {
			// jiti unavailable (e.g. compiled binary without the alias) — try native.
			const url = `${pathToFileURL(filePath).href}?t=${Date.now()}`;
			mod = await import(/* @vite-ignore */ url);
		}
	} catch (err) {
		const e = err as NodeJS.ErrnoException;
		if (e?.code === "ERR_UNKNOWN_FILE_EXTENSION") {
			warn?.(`permission-gate: ${path.basename(filePath)} found but no TS loader available — rename to rules.mjs`);
		} else {
			warn?.(`permission-gate: failed to load ${filePath}: ${(err as Error).message}`);
		}
		return {};
	}
	const exp = mod?.default;
	if (exp == null) {
		warn?.(`permission-gate: ${path.basename(filePath)} has no default export`);
		return {};
	}
	try {
		return typeof exp === "function" ? exp(helpers) : exp;
	} catch (err) {
		warn?.(`permission-gate: rules factory threw: ${(err as Error).message}`);
		return {};
	}
}

export interface ConfigLayers {
	userCode: GateConfig;
	userJson: GateConfig;
	project: GateConfig;
	/** Path of the active rules.{ts,mjs,js}, if any. */
	userCodePath?: string;
}

export async function loadConfig(cwd: string, helpers: GateHelpers, warn?: WarnFn): Promise<ConfigLayers> {
	const projectTs = path.join(cwd, ".pi", "permission-gate.ts");
	if (fs.existsSync(projectTs)) {
		warn?.(`permission-gate: ignoring ${projectTs} (project-level code config would execute untrusted code)`);
	}
	const userCodePath = userCodeConfigPath();
	return {
		userCode: userCodePath ? await importCodeConfig(userCodePath, helpers, warn) : {},
		userJson: readJsonSafe(userJsonConfigPath(), warn),
		project: readJsonSafe(projectJsonConfigPath(cwd), warn),
		userCodePath,
	};
}

// ── compilation ──────────────────────────────────────────────────────────

function compileEntry(r: RuleEntry, source: RuleSource, warn?: WarnFn): CompiledRule | undefined {
	const action = r.action ?? "prompt";
	if (r.test) {
		return { kind: "argv", label: r.label, action, reason: r.reason, source, test: r.test };
	}
	if (r.pattern === undefined) {
		warn?.(`permission-gate: rule "${r.label}" has neither pattern nor test — skipped`);
		return undefined;
	}
	try {
		const pattern = r.pattern instanceof RegExp
			? r.pattern
			: new RegExp(r.pattern, r.flags ?? "i");
		return { kind: "regex", label: r.label, action, reason: r.reason, source, pattern };
	} catch (err) {
		warn?.(`permission-gate: invalid regex for "${r.label}": ${(err as Error).message}`);
		return undefined;
	}
}

export function compileRules(layers: ConfigLayers, warn?: WarnFn): CompiledRule[] {
	const { userCode, userJson, project } = layers;
	const disabled = new Set([
		...(userCode.disabledRules ?? []),
		...(userJson.disabledRules ?? []),
		...(project.disabledRules ?? []),
	]);
	const compiled: CompiledRule[] = [];
	let hadError = false;

	const add = (entries: RuleEntry[] | undefined, source: RuleSource) => {
		for (const r of entries ?? []) {
			if (disabled.has(r.label)) continue;
			const c = compileEntry(r, source, warn);
			if (c) compiled.push(c);
			else hadError = true;
		}
	};

	// `rules` (full replace) applies to the *prompt* defaults only — the
	// block defaults protect the agent itself and are only removable via
	// `disabledRules`, so existing configs don't silently lose them.
	const promptBase = userCode.rules ?? userJson.rules;
	if (promptBase) add(promptBase, userCode.rules ? "user-ts" : "user-json");
	else add(DEFAULT_PROMPT_RULES, "built-in");
	add(DEFAULT_BLOCK_RULES, "built-in");
	add(userCode.extraRules, "user-ts");
	add(userJson.extraRules, "user-json");
	add(project.extraRules, "project");

	if (compiled.length === 0 && hadError) {
		warn?.("permission-gate: all rules failed, falling back to defaults");
		add(DEFAULT_PROMPT_RULES, "built-in");
		add(DEFAULT_BLOCK_RULES, "built-in");
	}
	return compiled;
}

// ── persistence (user JSON only — /gate add|rm write here) ───────────────

export function saveUserJson(cfg: GateConfig): void {
	try {
		fs.mkdirSync(configDir(), { recursive: true });
		fs.writeFileSync(userJsonConfigPath(), JSON.stringify(cfg, null, 2) + "\n");
	} catch {}
}

