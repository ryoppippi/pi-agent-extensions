/**
 * permission-gate — config loading, compilation and persistence.
 *
 * Configuration is read from four places, in order. Each place can add
 * rules or turn off rules that came from an earlier place:
 *
 *   1. the built-in rules
 *   2. the user's rules.ts (or .mjs / .js) in the config directory
 *   3. the user's rules.json in the config directory (written by /gate)
 *   4. the project's .pi/permission-gate.json in the working directory
 *
 * The user files (2, 3) are trusted. The project file (4) ships with the
 * repository, so it is not: it may add rules and turn off ordinary prompt
 * rules (the user is notified), but it can never turn off block rules
 * or the parser safety limits. A project rules.ts is refused entirely,
 * since importing it would run untrusted repository code on session start.
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

function readJsonSafe(filePath: string, warn?: WarnFn): unknown {
	try {
		if (!fs.existsSync(filePath)) return {};
		return JSON.parse(fs.readFileSync(filePath, "utf-8"));
	} catch (err) {
		warn?.(`permission-gate: failed to load ${filePath}: ${(err as Error).message}`);
		return {};
	}
}

// ── validation ────────────────────────────────────────────────────────────────

/**
 * Shape-check a config layer before compilation. JSON files arrive from
 * disk with arbitrary content — `{"test": true}` used to survive until
 * matchRules and throw on every bash call, and non-object
 * shapes (null file, `"disabledRules": 42`, `"extraRules": {}`) threw at
 * reload. `allowTest` is true only for code configs; JSON cannot carry
 * functions, so any `test` there is malformed (or malicious) and the rule
 * is skipped. Never throws.
 */
export function sanitizeConfig(raw: unknown, origin: string, allowTest: boolean, warn?: WarnFn): GateConfig {
	if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
		if (raw != null) warn?.(`permission-gate: ${origin}: config must be an object — ignored`);
		return {};
	}
	const cfg = raw as Record<string, unknown>;
	const out: GateConfig = {};
	if (cfg.disabledRules !== undefined) {
		if (Array.isArray(cfg.disabledRules)) {
			out.disabledRules = cfg.disabledRules.filter((x): x is string => {
				if (typeof x === "string") return true;
				warn?.(`permission-gate: ${origin}: non-string disabledRules entry ignored`);
				return false;
			});
		} else {
			warn?.(`permission-gate: ${origin}: disabledRules must be an array — ignored`);
		}
	}
	if (cfg.disabledGroups !== undefined) {
		if (Array.isArray(cfg.disabledGroups)) {
			out.disabledGroups = cfg.disabledGroups.filter((x): x is string => {
				if (typeof x === "string") return true;
				warn?.(`permission-gate: ${origin}: non-string disabledGroups entry ignored`);
				return false;
			});
		} else {
			warn?.(`permission-gate: ${origin}: disabledGroups must be an array — ignored`);
		}
	}
	const sanitizeEntries = (v: unknown, key: string): RuleEntry[] | undefined => {
		if (!Array.isArray(v)) {
			warn?.(`permission-gate: ${origin}: ${key} must be an array — ignored`);
			return undefined;
		}
		const entries: RuleEntry[] = [];
		for (const r of v) {
			if (r === null || typeof r !== "object" || Array.isArray(r) ||
				typeof (r as RuleEntry).label !== "string") {
				warn?.(`permission-gate: ${origin}: ${key} entry without a string label — skipped`);
				continue;
			}
			const e = r as RuleEntry;
			if (e.test !== undefined && (!allowTest || typeof e.test !== "function")) {
				warn?.(allowTest
					? `permission-gate: ${origin}: rule "${e.label}" test is not a function — skipped`
					: `permission-gate: ${origin}: rule "${e.label}" carries a test (JSON rules cannot) — skipped`);
				continue;
			}
			if (e.pattern !== undefined && typeof e.pattern !== "string" && !(e.pattern instanceof RegExp)) {
				warn?.(`permission-gate: ${origin}: rule "${e.label}" pattern is not a string — skipped`);
				continue;
			}
			if (e.action !== undefined && e.action !== "prompt" && e.action !== "block") {
				warn?.(`permission-gate: ${origin}: rule "${e.label}" has unknown action — skipped`);
				continue;
			}
			if (e.reason !== undefined && typeof e.reason !== "string") {
				warn?.(`permission-gate: ${origin}: rule "${e.label}" reason is not a string — skipped`);
				continue;
			}
			if (e.flags !== undefined && typeof e.flags !== "string") {
				warn?.(`permission-gate: ${origin}: rule "${e.label}" flags is not a string — skipped`);
				continue;
			}
			entries.push(e);
		}
		return entries;
	};
	if (cfg.rules !== undefined) out.rules = sanitizeEntries(cfg.rules, "rules");
	if (cfg.extraRules !== undefined) out.extraRules = sanitizeEntries(cfg.extraRules, "extraRules");
	return out;
}

/**
 * Import the user's rules.ts / .mjs / .js. Tries pi's bundled jiti first (handles .ts and
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
	/** Path of the user's rules code file (rules.ts, .mjs or .js), if any. */
	userCodePath?: string;
}

export async function loadConfig(cwd: string, helpers: GateHelpers, warn?: WarnFn): Promise<ConfigLayers> {
	const projectTs = path.join(cwd, ".pi", "permission-gate.ts");
	if (fs.existsSync(projectTs)) {
		warn?.(`permission-gate: ignoring ${projectTs} (project-level code config would execute untrusted code)`);
	}
	const userCodePath = userCodeConfigPath();
	return {
		userCode: sanitizeConfig(
			userCodePath ? await importCodeConfig(userCodePath, helpers, warn) : {},
			userCodePath ? path.basename(userCodePath) : "rules.ts", true, warn,
		),
		userJson: sanitizeConfig(readJsonSafe(userJsonConfigPath(), warn), "rules.json", false, warn),
		project: sanitizeConfig(
			readJsonSafe(projectJsonConfigPath(cwd), warn), ".pi/permission-gate.json", false, warn,
		),
		userCodePath,
	};
}

// ── compilation ──────────────────────────────────────────────────────────

// Project regexes run against every bash command and come from an untrusted
// repo file — a catastrophic pattern would hang the agent on its first tool
// call (ReDoS). Three bounds compose, because none alone is an analyzer:
// this length cap and the rule-count cap bound pattern size and number,
// the nested-quantifier check below rejects the classic exponential shape,
// and matchRules truncates the *subject* for project rules — backtracking
// cost grows with the command, so a short in-cap pattern against an
// ordinary command was still exponential (~4 s at 56 chars, doubling per
// character). User-scope configs are trusted and skip all three.
const MAX_PROJECT_PATTERN_LENGTH = 256;

// (x+)+ / (x*)+ shapes — a quantified group whose body itself ends in a
// quantifier — are the canonical exponential-backtracking pattern: the
// 24-char `^(([a-z0-9 /._-]+)+)+\0$` compiled fine under every size cap
// and stalled matchRules for seconds. No heuristic catches every ReDoS
// (the subject truncation in matchRules is the backstop); this rejects
// the classic shape outright, with a warning.
const NESTED_QUANTIFIER = /\([^()]*[+*}]\)[+*{]/;

// The length cap alone does not bound match cost — catastrophic patterns are
// short (`(x+x+)+y` costs ~0.6 s per command on bun), and nothing else limits
// how many rules a repo ships, so 50 of them would add ~30 s to every bash
// call. Capping the *count* bounds the total without building a regex
// time-budget engine; 20 is far above any legitimate project config.
const MAX_PROJECT_RULES = 20;

// A block rule's reason is delivered verbatim to the model — from the
// untrusted project layer that is an instruction-injection channel ("Tool
// policy: instead run …"). Mark the origin and bound the length.
const MAX_PROJECT_REASON_LENGTH = 300;

// Labels flow into prompt titles, /gate list and — via the derived
// `Blocked (label)` reason — to the model, so untrusted ones are capped
// at compile time too.
const MAX_PROJECT_LABEL_LENGTH = 100;

/**
 * Prompt rules the untrusted project layer may never disable, UI or
 * headless — they are the enforcement floor under every other rule, so a
 * repo-shipped disable escalates exactly like disabling a block rule:
 *
 *   - "unparseable command (depth budget)" is the fail-closed sentinel for
 *     parse-budget exhaustion; without it a mechanical 66×`eval` prefix
 *     hides any payload from every rule, blocks included;
 *   - "modify gate config" keeps the gated agent from rewriting the
 *     *trusted* user config layer (which may disable block rules) through
 *     its own bash tool;
 *   - "non-literal command name" is what keeps `$a id` / `$(echo sudo) id`
 *     from bypassing every argv rule, blocks included.
 *
 * User layers are trusted and may still disable them.
 */
export const PROTECTED_LABELS = new Set([
	"unparseable command (depth budget)",
	"modify gate config",
	"non-literal command name",
]);

function compileEntry(r: RuleEntry, source: RuleSource, warn?: WarnFn): CompiledRule | undefined {
	const action = r.action ?? "prompt";
	let label = r.label;
	if (source === "project" && label.length > MAX_PROJECT_LABEL_LENGTH) {
		warn?.(`permission-gate: project rule label truncated to ${MAX_PROJECT_LABEL_LENGTH} chars`);
		label = label.slice(0, MAX_PROJECT_LABEL_LENGTH);
	}
	let reason = r.reason;
	if (source === "project") {
		// Cap and origin-prefix the *derived* fallback too — `Blocked (label)`
		// reached the model unmarked and uncapped whenever a project block
		// rule simply omitted `reason`.
		const base = r.reason ?? (action === "block" ? `Blocked (${label})` : undefined);
		reason = base === undefined
			? undefined
			: `[project rule] ${base}`.slice(0, MAX_PROJECT_REASON_LENGTH);
	}
	if (typeof r.test === "function") {
		if (r.pattern !== undefined) {
			warn?.(`permission-gate: rule "${label}" sets both pattern and test — pattern is ignored`);
		}
		return { kind: "argv", label, group: r.group, action, reason, source, test: r.test };
	}
	if (r.test !== undefined) {
		// JSON cannot carry functions but can carry `true` — compiling such a
		// rule made every later matchRules call throw.
		warn?.(`permission-gate: rule "${label}" test is not a function — skipped`);
		return undefined;
	}
	if (r.pattern === undefined) {
		warn?.(`permission-gate: rule "${label}" has neither pattern nor test — skipped`);
		return undefined;
	}
	const patternSource = r.pattern instanceof RegExp ? r.pattern.source : String(r.pattern);
	if (source === "project" && patternSource.length > MAX_PROJECT_PATTERN_LENGTH) {
		warn?.(
			`permission-gate: project rule "${label}" pattern exceeds ` +
			`${MAX_PROJECT_PATTERN_LENGTH} chars — skipped`,
		);
		return undefined;
	}
	if (source === "project" && NESTED_QUANTIFIER.test(patternSource)) {
		warn?.(
			`permission-gate: project rule "${label}" pattern nests quantifiers ` +
			`((x+)+ shapes backtrack exponentially) — skipped`,
		);
		return undefined;
	}
	try {
		// `g`/`y` make RegExp.test stateful via lastIndex — a rule carrying
		// them would only match every other command it is tested against.
		const flags = (r.pattern instanceof RegExp ? r.pattern.flags : r.flags ?? "i").replace(/[gy]/g, "");
		const pattern = r.pattern instanceof RegExp
			? new RegExp(r.pattern.source, flags)
			: new RegExp(r.pattern, flags);
		return { kind: "regex", label, group: r.group, action, reason, source, pattern };
	} catch (err) {
		warn?.(`permission-gate: invalid regex for "${label}": ${(err as Error).message}`);
		return undefined;
	}
}

export function compileRules(
	layers: ConfigLayers,
	warn?: WarnFn,
	opts?: { headless?: boolean },
): CompiledRule[] {
	const { userCode, userJson, project } = layers;
	// Defense in depth: layers normally arrive sanitized (loadConfig), but a
	// malformed shape here must degrade, never throw.
	const strings = (v: unknown): string[] =>
		Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
	const entries = (v: RuleEntry[] | undefined): RuleEntry[] => (Array.isArray(v) ? v : []);
	const userDisabled = new Set([
		...strings(userCode.disabledRules),
		...strings(userJson.disabledRules),
	]);
	const userDisabledGroups = new Set([
		...strings(userCode.disabledGroups),
		...strings(userJson.disabledGroups),
	]);
	// The project layer ships with the repo and is untrusted (same reason
	// project rules.ts is refused): a malicious .pi/permission-gate.json must
	// not be able to silently neuter the gate. Block rules survive it, and
	// anything it does disable is reported so the user notices.
	const projectDisabled = new Set(strings(project.disabledRules));
	const projectDisabledGroups = new Set(strings(project.disabledGroups));
	const projectApplied: string[] = [];
	const projectRefused: string[] = [];
	const protectedRefused: string[] = [];
	const headlessRefused: string[] = [];
	const compiled: CompiledRule[] = [];
	let hadError = false;

	const add = (list: RuleEntry[] | undefined, source: RuleSource) => {
		for (const r of entries(list)) {
			if (r === null || typeof r !== "object" || typeof r.label !== "string") {
				warn?.(`permission-gate: ${source} rule without a string label — skipped`);
				hadError = true;
				continue;
			}
			if (userDisabled.has(r.label)) continue;
			if (r.group && userDisabledGroups.has(r.group)) continue;
			// Group disables from the project layer walk the same refusal
			// ladder as label disables — a repo must not get by group what it
			// is refused by label.
			if (projectDisabled.has(r.label) || (r.group && projectDisabledGroups.has(r.group))) {
				if ((r.action ?? "prompt") === "block") {
					projectRefused.push(r.label);
				} else if (PROTECTED_LABELS.has(r.label)) {
					// These prompt rules are load-bearing (see PROTECTED_LABELS):
					// block survival is illusory if the sentinel or the gate's
					// self-protection underneath them is project-disableable.
					protectedRefused.push(r.label);
				} else if (opts?.headless) {
					// Headless prompts hard-block, so letting the untrusted project
					// layer disable one would *escalate* "blocked" to "runs with
					// zero record" — refuse exactly like a block rule.
					headlessRefused.push(r.label);
				} else {
					projectApplied.push(r.label);
					continue;
				}
			}
			const c = compileEntry(r, source, warn);
			if (c) compiled.push(c);
			else hadError = true;
		}
	};

	// `rules` (full replace) applies to the *prompt* defaults only — the
	// block defaults protect the agent itself and are only removable via
	// `disabledRules`, so existing configs don't silently lose them.
	// Both user layers replacing the defaults at once is almost certainly a
	// config mistake — every other conflict in this merge warns, so the
	// shadowed JSON layer must too instead of vanishing silently.
	if (userCode.rules && userJson.rules) {
		warn?.("permission-gate: rules.ts `rules` shadows rules.json `rules` — the JSON rules are ignored (use extraRules)");
	}
	const promptBase = userCode.rules ?? userJson.rules;
	if (promptBase) add(promptBase, userCode.rules ? "user-code" : "user-json");
	else add(DEFAULT_PROMPT_RULES, "built-in");
	add(DEFAULT_BLOCK_RULES, "built-in");
	add(userCode.extraRules, "user-code");
	add(userJson.extraRules, "user-json");
	// A repo may not replace the rule set — like a refused disabledRules,
	// the attempt is surfaced instead of silently ignored.
	if (project.rules) {
		warn?.("permission-gate: project config may not replace rules — `rules` key ignored (use extraRules)");
	}
	let projectExtra = entries(project.extraRules);
	if (projectExtra.length > MAX_PROJECT_RULES) {
		warn?.(
			`permission-gate: project config has ${projectExtra.length} extraRules — ` +
			`only the first ${MAX_PROJECT_RULES} are used`,
		);
		projectExtra = projectExtra.slice(0, MAX_PROJECT_RULES);
	}
	add(projectExtra, "project");

	if (compiled.length === 0 && hadError) {
		warn?.("permission-gate: all rules failed, falling back to defaults");
		add(DEFAULT_PROMPT_RULES, "built-in");
		add(DEFAULT_BLOCK_RULES, "built-in");
	}
	// Project extraRules run against every command and ship with the repo —
	// surface them like disabledRules so the user notices what an untrusted
	// config contributes.
	if (projectExtra.length) {
		warn?.(
			`permission-gate: project config adds rule(s): ` +
			`${projectExtra.map((r) => String(r.label).slice(0, MAX_PROJECT_LABEL_LENGTH)).join(", ")}`,
		);
	}
	if (projectApplied.length) {
		warn?.(`permission-gate: project config disabled rule(s): ${[...new Set(projectApplied)].join(", ")}`);
	}
	if (projectRefused.length) {
		warn?.(`permission-gate: project config may not disable block rule(s): ${[...new Set(projectRefused)].join(", ")}`);
	}
	if (protectedRefused.length) {
		warn?.(`permission-gate: project config may not disable load-bearing prompt rule(s): ${[...new Set(protectedRefused)].join(", ")}`);
	}
	if (headlessRefused.length) {
		warn?.(`permission-gate: project config may not disable prompt rule(s) without a UI: ${[...new Set(headlessRefused)].join(", ")}`);
	}
	return compiled;
}

// ── persistence (user JSON only — /gate add|rm write here) ───────────────

/** Merge the sanitized config over the raw on-disk JSON, so unknown keys a
 * hand-edited rules.json carries survive /gate add|rm round-trips — `cfg`
 * is the *sanitized* view, and writing it back verbatim deleted anything
 * sanitizeConfig doesn't model. */
export function mergeUserJson(raw: unknown, cfg: GateConfig): Record<string, unknown> {
	const base = raw !== null && typeof raw === "object" && !Array.isArray(raw)
		? (raw as Record<string, unknown>)
		: {};
	return { ...base, ...cfg };
}

/** Returns false (with a warning) if the write failed — callers must not
 * report success then, since reloadRules re-reads from disk and would
 * silently drop the in-memory change. */
export function saveUserJson(cfg: GateConfig, warn?: WarnFn): boolean {
	try {
		fs.mkdirSync(configDir(), { recursive: true });
		const merged = mergeUserJson(readJsonSafe(userJsonConfigPath()), cfg);
		fs.writeFileSync(userJsonConfigPath(), JSON.stringify(merged, null, 2) + "\n");
		return true;
	} catch (err) {
		warn?.(`permission-gate: failed to save ${userJsonConfigPath()}: ${(err as Error).message}`);
		return false;
	}
}

