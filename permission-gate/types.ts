/**
 * permission-gate — shared types.
 */

import type { pipelines, simpleCommands } from "./shell.ts";

/** How a matched rule is handled. */
export type Action = "prompt" | "block";

/** Where a compiled rule came from (for /gate list and /gate rm). */
export type RuleSource = "built-in" | "user-ts" | "user-json" | "project";

/** A pipeline as seen by argv rules: one string[] per command joined by |. */
export type ArgvPipeline = string[][];

/**
 * Rule as written in config. Exactly one of `pattern` / `test` must be set.
 * `pattern` matches the raw command string; `test` receives tokenized
 * pipelines (see shell.ts) and is called once per pipeline, including those
 * inside $() / <() substitutions.
 */
export interface RuleEntry {
	label: string;
	/** Regex on the raw command string. String is compiled with `flags` (default "i"). */
	pattern?: string | RegExp;
	flags?: string;
	/** Argv predicate on a tokenized pipeline. */
	test?: (pipeline: ArgvPipeline) => boolean;
	/** Default: "prompt". */
	action?: Action;
	/** Message returned to the model on block. Defaults to a generic one derived from `label`. */
	reason?: string;
}

/** Config file shape (rules.ts / rules.json / .pi/permission-gate.json). */
export interface GateConfig {
	/** Replace the built-in *prompt* defaults entirely. Block defaults are only removable via `disabledRules`. */
	rules?: RuleEntry[];
	/** Extra rules appended on top of defaults. */
	extraRules?: RuleEntry[];
	/** Disable rules (built-in or from an earlier layer) by label. */
	disabledRules?: string[];
}

/** Helpers passed to a rules.ts factory so it needs no cross-package imports. */
export interface GateHelpers {
	simpleCommands: typeof simpleCommands;
	pipelines: typeof pipelines;
	searchPaths: (argv: string[]) => string[];
}

/** rules.ts default export: either a config object or a factory receiving helpers. */
export type GateConfigModule = GateConfig | ((helpers: GateHelpers) => GateConfig);

/** Rule after compilation. */
export type CompiledRule = {
	label: string;
	action: Action;
	reason?: string;
	source: RuleSource;
} & (
	| { kind: "regex"; pattern: RegExp }
	| { kind: "argv"; test: (pipeline: ArgvPipeline) => boolean }
);

export type WarnFn = (msg: string) => void;

export type GateResult = { allow: true } | { allow: false; reason: string };
