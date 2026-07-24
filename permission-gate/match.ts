/**
 * permission-gate — rule matching against a bash command string.
 *
 * Pure rule matching: all command-structure analysis (tokenizing, pipeline
 * collection, script recursion) lives in shell.ts. Kept free of pi imports
 * so tests can exercise the exact code paths the extension uses (index.ts
 * only wires these into the tool_call event).
 */

import type { ArgvPipeline, CompiledRule } from "./types.ts";
import { collectPipelines, tokenize } from "./shell.ts";

/**
 * Project regexes match against at most this many characters of the
 * command (raw and decoded). The compile-time caps in config.ts bound
 * pattern size, count and the classic exponential shape — not match
 * *time*: backtracking cost grows with the subject, so a heuristic-
 * evading pattern must still run against a bounded subject or a hostile
 * repo stalls the gate inside tool_call. 512 chars is far beyond what a
 * legitimate project rule targets; user and built-in rules are trusted
 * and keep seeing the full string.
 */
export const MAX_PROJECT_MATCH_LENGTH = 512;

/** All rules matching `command`. Pipelines and the decoded spelling are
 * computed lazily and at most once per call. */
export function matchRules(command: string, rules: CompiledRule[]): CompiledRule[] {
	let argvPipes: ArgvPipeline[] | undefined;
	let decoded: string | undefined;
	// Regex rules run against the raw string *and* the tokenizer-decoded
	// words (quotes stripped, escapes decoded, redirect targets included —
	// they are word tokens at this level). Raw-only matching let a quote
	// splice hide any substring a regex rule looks for: the gate
	// self-protection rule missed
	// `~/.config/'pi-agent-extensions'/permission-gate/rules.json` while
	// the argv rules had long since decoded the same spelling.
	const decode = () =>
		(decoded ??= tokenize(command)
			.map((t) => (t.type === "word" || t.type === "op" ? t.value : ""))
			.filter(Boolean)
			.join(" "));
	const clip = (s: string, r: CompiledRule) =>
		r.source === "project" && s.length > MAX_PROJECT_MATCH_LENGTH
			? s.slice(0, MAX_PROJECT_MATCH_LENGTH)
			: s;
	return rules.filter((r) =>
		r.kind === "regex"
			? r.pattern.test(clip(command, r)) || r.pattern.test(clip(decode(), r))
			: (argvPipes ??= collectPipelines(command)).some((p) => r.test(p)),
	);
}
