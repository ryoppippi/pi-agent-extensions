/**
 * permission-gate — shell command structure: pipelines and script traversal.
 *
 * Composes the tokenizer (tokenize.ts) with the wrapper/executor knowledge
 * (argv.ts) into the shapes rules consume:
 *
 *   - `pipelines`: assembles tokens into pipelines of simple commands,
 *     deciding which herestrings/heredoc bodies are scripts vs. data.
 *   - `scriptSources`: the single list of every script a command carries
 *     (substitutions, inline scripts, deferred tasks).
 *   - `simpleCommands` / `collectPipelines`: the two recursive walks over
 *     that list — flat argvs for simple rules, pipelines (plus synthesized
 *     `fetcher | shell` correlations) for the matcher.
 *
 * Also re-exports the public surface of both layers, so consumers keep a
 * single import point.
 */

import type { ArgvPipeline } from "./types.ts"; // type-only: erased, no runtime cycle
import {
	braceExpand, REDIRECT_OPS, hasSubPlaceholder, PARSE_BUDGET_SENTINEL, tokenize,
} from "./tokenize.ts";
import {
	basenameCmd, deferredScripts, EXEC_BUILTINS, FETCHERS, isDecoder,
	nestedScripts, SHELLS, SOURCE_BUILTINS, STDIN_RUNNERS, unwrap,
} from "./argv.ts";

export {
	collapseBrackets, hasSubPlaceholder, heredocSubstitutions, isSubPlaceholder,
	PARSE_BUDGET_SENTINEL, tokenize, type Token,
} from "./tokenize.ts";
export {
	deferredScripts, EXEC_BUILTINS, FETCHERS, isDecoder,
	MAX_UNWRAP_STEPS, nestedScripts, SHELLS, SOURCE_BUILTINS, STDIN_RUNNERS,
	unwrap, unwrapSteps,
} from "./argv.ts";

// Reserved words that precede a command in compound statements. Skipped at
// command position so `then sudo x` / `do rm -r f` still expose the real
// command. `for f in …` degrades to argv ["f","in",…] — harmless noise.
// `coproc <cmd>` runs its command asynchronously with argv[0] hidden at
// argv[1] — skipping it exposes the real command (the compound
// `coproc NAME { … }` form is already split at the `{` boundary).
// `in` is skipped too: after `case $x` the subject word is dropped (see
// pipelines), leaving `in` at command position, where it is never a
// program name.
const RESERVED = new Set([
	"if", "then", "elif", "else", "fi",
	"while", "until", "for", "do", "done",
	"case", "esac", "in", "{", "}", "!", "time", "function", "coproc",
]);

/** One command in a pipeline: its argv plus the inner scripts of any
 * command/process substitutions appearing in its words. */
export interface ShellCommand {
	argv: string[];
	subs: string[];
	/** Inner scripts of output process substitutions `>(…)` — kept apart
	 * from `subs` because their processes *consume* this pipeline's output
	 * (the out-sub synthesis needs the direction). */
	outSubs: string[];
	/** True when this command executes its stdin and that stdin is fed by a
	 * substitution spelled as a redirect target or herestring (`bash <
	 * <(curl u)`, `bash <<< "$(curl u)"`) — the placeholder never reaches
	 * argv, so the fetch/decoder synthesis needs this flag to correlate. */
	stdinSub: boolean;
}

/** Commands connected by `|` / `|&`, in order. */
export type Pipeline = ShellCommand[];

/**
 * Parse a command string into pipelines of simple commands. Pipelines are
 * separated by `;`, `&&`, `||`, `&`, newlines and parentheses. Substitution
 * scripts are attached to the command they appear in (not parsed further;
 * callers recurse via `pipelines(sub)` if needed). Leading VAR=value
 * prefixes are dropped so argv[0] is the program.
 */
export function pipelines(command: string): Pipeline[] {
	const result: Pipeline[] = [];
	let pipeline: Pipeline = [];
	let argv: string[] = [];
	let subs: string[] = [];
	let outSubs: string[] = [];
	// Pending stdin data (herestrings and heredoc bodies) — script or data
	// depending on the receiving command, decided in flushCommand.
	let herestrings: string[] = [];
	let heredocs: { value: string; subs: string[] }[] = [];
	// The redirect operator whose target word is still pending, so the
	// target can be told apart from arguments — and so a herestring aimed
	// at a shell can be recognized as a script rather than dropped.
	let pendingRedirect: string | null = null;
	// True when a `<` redirect target carried a substitution placeholder —
	// that substitution's output becomes this command's stdin (`bash <
	// <(curl u)`); the target word itself is dropped, so flushCommand
	// records the fact on the command instead.
	let redirectSub = false;
	// Sequence number of the current simple command, counted exactly like
	// the tokenizer counts it (see tokenize). Heredoc tokens carry the seq
	// of the command that had the << operator, so an operator between <<
	// and the newline (`bash <<EOF | cat`) cannot hand the body to
	// whichever command happens to be open when the body is read — that
	// mis-binding was both a bypass and a `cat <<EOF && bash` false
	// positive.
	let seq = 0;
	const flushedBySeq = new Map<number, { cmd: ShellCommand; pl: Pipeline }>();
	// True right after the RESERVED word `time` — its -p / -- options must
	// be skipped too or they land at argv[0] and hide the real command.
	let afterTime = false;
	// True right after `case` — the next word is the case *subject*
	// (`case $x in …`), an expansion sitting at what looks like command
	// position; skipping it keeps the non-literal-command rule from
	// misreading it as a program name.
	let caseWord = false;

	// Shells run their stdin as a script; GNU parallel hands each line to
	// one; `.`/`source` execute a stdin-spelled file in the current shell.
	const executesStdin = (head: string | undefined) =>
		head !== undefined &&
		(SHELLS.has(head) || STDIN_RUNNERS.has(head) || SOURCE_BUILTINS.has(head));

	const flushCommand = () => {
		// A herestring or heredoc aimed at a shell puts a *script* on its stdin
		// (`bash <<< 'sudo rm -rf /'`, `bash <<EOF … EOF`) — dropping it like a
		// file target would hide the script from every rule. Decided here,
		// once the final argv is known, because bash accepts redirections
		// *before* the command word (`<<<'rm -rf /' bash`). For non-shells
		// (`cat <<EOF … EOF`) the body stays data — minus the substitutions
		// bash expands in unquoted-delimiter heredoc bodies regardless of the
		// receiver — except parallel, which runs its stdin through a shell.
		const head = unwrap(argv)[0];
		const execsStdin = executesStdin(head);
		// A redirect target or herestring carrying a substitution placeholder
		// feeds that substitution's output to this command's stdin — when the
		// command executes stdin, that is fetch-and-execute with one character
		// changed (`bash < <(curl u)` vs `bash <(curl u)`), so mark it for the
		// same synthesis the argv-placeholder spelling gets.
		const stdinSub = execsStdin && (redirectSub || herestrings.some(hasSubPlaceholder));
		if (herestrings.length && execsStdin) subs.push(...herestrings);
		for (const h of heredocs) {
			if (execsStdin) subs.push(h.value);
			else subs.push(...h.subs);
		}
		herestrings = [];
		heredocs = [];
		redirectSub = false;
		const cmd: ShellCommand = { argv, subs, outSubs, stdinSub };
		flushedBySeq.set(seq, { cmd, pl: pipeline });
		if (argv.length || subs.length || outSubs.length) pipeline.push(cmd);
		argv = [];
		subs = [];
		outSubs = [];
		afterTime = false;
		caseWord = false;
	};
	const flushPipeline = () => {
		flushCommand();
		if (pipeline.length) result.push(pipeline);
		pipeline = [];
	};

	// Late-bind a heredoc whose command was already flushed — an operator
	// between << and the newline means the body token arrives after its
	// command.
	const attachHeredoc = (token: { value: string; subs: string[]; cmd: number }) => {
		const rec = flushedBySeq.get(token.cmd);
		if (!rec) return;
		const head = unwrap(rec.cmd.argv)[0];
		const add = executesStdin(head) ? [token.value] : token.subs;
		if (!add.length) return;
		rec.cmd.subs.push(...add);
		// The command (or its whole pipeline) may have been dropped as empty
		// at flush time — reinstate it now that it carries a script.
		if (!rec.pl.includes(rec.cmd)) rec.pl.push(rec.cmd);
		if (rec.pl !== pipeline && !result.includes(rec.pl)) result.push(rec.pl);
	};

	for (const token of tokenize(command)) {
		// Standalone { } group commands without being operators; treat them as
		// boundaries so `function f { sudo x; }` doesn't bury sudo mid-argv.
		if (token.type === "word" && (token.value === "{" || token.value === "}")) {
			flushPipeline();
			seq++; // the tokenizer counts these boundaries too
			continue;
		}
		if (token.type === "op") {
			if (REDIRECT_OPS.has(token.value)) {
				pendingRedirect = token.value;
				continue;
			}
			pendingRedirect = null;
			// Heredoc delimiter/body are consumed by the tokenizer; << itself does
			// not end the command.
			if (token.value === "<<" || token.value === "<<-") continue;
			if (token.value === "|" || token.value === "|&") flushCommand();
			else flushPipeline();
			seq++;
			continue;
		}
		if (token.type === "sub") {
			(token.out ? outSubs : subs).push(token.value);
			continue;
		}
		if (token.type === "heredoc") {
			if (token.cmd === seq) heredocs.push(token);
			else attachHeredoc(token);
			continue;
		}
		if (pendingRedirect) {
			const op = pendingRedirect;
			pendingRedirect = null;
			// Herestring data is held until flushCommand decides whether the
			// command is a shell (see comment there); other redirect targets
			// are dropped — except that an input target carrying a
			// substitution placeholder pipes that substitution's output into
			// this command, which flushCommand must know.
			if (op === "<<<") herestrings.push(token.value);
			else if (op === "<" && hasSubPlaceholder(token.value)) redirectSub = true;
			continue;
		}
		// Brace expansion may split one word into several (`{rm,-rf,/}` runs
		// `rm -rf /`), so every expanded word lands in argv individually.
		for (const w of braceExpand(token.value)) {
			if (argv.length === 0) {
				if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(w)) continue;
				if (RESERVED.has(w)) {
					// bash's `time` keyword accepts -p and -- before the pipeline
					// it times — skipping only the keyword left "-p" at argv[0],
					// hiding the real command from every rule.
					afterTime = w === "time";
					caseWord = w === "case";
					continue;
				}
				if (afterTime && (w === "-p" || w === "--")) continue;
				afterTime = false;
				if (caseWord) { caseWord = false; continue; } // the case subject
				// Path-spelled commands resolve to the basename (see basenameCmd).
				argv.push(basenameCmd(w));
				continue;
			}
			argv.push(w);
		}
	}
	flushPipeline();
	return result;
}

/**
 * Recursion budget for script re-parsing. Adversarial nesting
 * (`"$(".repeat(3500)`) must degrade to "stop recursing", never overflow
 * the stack — the tool_call handler contract is "never throw" (same
 * budget idea as braceExpand).
 */
export const MAX_PARSE_DEPTH = 64;

/**
 * Cap on pipeline stages analyzed per pipeline. Stage handling used to be
 * quadratic (upstream prefix slices), so an 80KB `a|a|a|…` command stalled
 * the gate ~12s inside tool_call — and a hung gate is a disabled gate.
 * 512 is far beyond any legitimate pipeline.
 */
export const MAX_PIPELINE_STAGES = 512;

// PARSE_BUDGET_SENTINEL (re-exported above) lives in tokenize.ts so that
// argv.ts's unwrap-step budget can emit it without an import cycle.

/**
 * Every script source a command carries: its command/process substitution
 * scripts, then the inline scripts (`sh -c '…'`, `eval …`) and deferred
 * tasks (`pueue add …`, `tmux new-session …`, `find -exec …`) of the
 * unwrapped argv. This is the single walk both `simpleCommands` and
 * `collectPipelines` recurse through — add new script sources here so the
 * two can never diverge. Order contract: `cmd.subs` come first (in order),
 * then `cmd.outSubs` (in order), so callers can correlate the leading
 * entries back to the substitutions.
 */
export function scriptSources(cmd: ShellCommand): string[] {
	const argv = unwrap(cmd.argv);
	return [...cmd.subs, ...cmd.outSubs, ...nestedScripts(argv), ...deferredScripts(argv)];
}

/**
 * Flatten a command string into simple commands (argv arrays), recursing
 * into every script source. Convenience wrapper over `pipelines`.
 */
export function simpleCommands(command: string): string[][] {
	const commands: string[][] = [];
	const walk = (script: string, depth: number) => {
		// Fail closed on depth exhaustion (see PARSE_BUDGET_SENTINEL) so this
		// walk and collectPipelines can never disagree about giving up.
		if (depth > MAX_PARSE_DEPTH) {
			commands.push([PARSE_BUDGET_SENTINEL]);
			return;
		}
		for (const pipeline of pipelines(script)) {
			for (const cmd of pipeline) {
				if (cmd.argv.length) commands.push(cmd.argv);
				for (const s of scriptSources(cmd)) walk(s, depth + 1);
			}
		}
	};
	walk(command, 0);
	return commands;
}

/**
 * A shell (or eval) consuming a `$(…)`/`<(…)` substitution executes its
 * output — when curl/wget produce it, synthesize the equivalent
 * `curl … | shell` pipeline so the pipe-to-shell rule correlates the two
 * (`bash <(curl u)`, `eval "$(curl u)"`, `sh -c "$(wget -qO- u)"`).
 * Decoders get the same synthesis (`eval "$(base64 -d f)"`) for the "shell
 * executes decoded data" rule. The substitution may sit in argv (a
 * placeholder word) or feed stdin via a redirect target or herestring
 * (`bash < <(curl u)`, `bash <<< "$(curl u)"` — `cmd.stdinSub`); both
 * spellings execute the same bytes. Plain substitutions (`$(git rev-parse
 * HEAD)`) synthesize nothing and stay clean. `subPipes` are the
 * already-collected pipelines of `cmd.subs`, in the same order.
 */
function synthesizeFetchExecPipelines(cmd: ShellCommand, subPipes: ArgvPipeline[][]): ArgvPipeline[] {
	const argv = unwrap(cmd.argv);
	if (!(SHELLS.has(argv[0]) || EXEC_BUILTINS.has(argv[0]))) return [];
	if (!cmd.argv.some(hasSubPlaceholder) && !cmd.stdinSub) return [];
	const synthesized: ArgvPipeline[] = [];
	for (const pipes of subPipes) {
		for (const sp of pipes) {
			if (sp.some((stage) => FETCHERS.has(unwrap(stage)[0]) || isDecoder(stage))) {
				synthesized.push([...sp, cmd.argv]);
			}
		}
	}
	return synthesized;
}

/**
 * An output process substitution whose sub-pipeline starts with a bare
 * shell (`tee >(sh)`, `cmd > >(bash)`) feeds the surrounding pipeline's
 * data into that shell — synthesize `upstream… | shell` so "shell executes
 * stdin" can correlate the two. `upstream` is the outer pipeline up to and
 * including the command carrying the substitution; `outSubPipes` are the
 * already-collected pipelines of `cmd.outSubs`. The stdin rule applies its
 * own bareness check, so `>(sh -c '…')` is synthesized but does not fire.
 */
function synthesizeOutSubPipelines(upstream: ArgvPipeline, outSubPipes: ArgvPipeline[][]): ArgvPipeline[] {
	if (!upstream.length) return [];
	const synthesized: ArgvPipeline[] = [];
	for (const pipes of outSubPipes) {
		for (const sp of pipes) {
			if (sp.length && SHELLS.has(unwrap(sp[0])[0])) {
				synthesized.push([...upstream, ...sp]);
			}
		}
	}
	return synthesized;
}

/** Pipelines as argv lists, recursing into every script source (command/
 * process substitutions, inline scripts, deferred tasks) and synthesizing
 * `fetcher | shell` pipelines for substitution-fed shells. */
export function collectPipelines(script: string, depth = 0): ArgvPipeline[] {
	// Depth budget: adversarial nesting ("$(".repeat(3500)) must degrade to
	// "stop recursing", not overflow the stack — event handlers must never
	// throw. Exhaustion fails *closed*: the sentinel pipeline keeps 66-deep
	// nesting from hiding its payload from every rule (see the constant).
	if (depth > MAX_PARSE_DEPTH) return [[[PARSE_BUDGET_SENTINEL]]];
	return pipelines(script).flatMap((full) => {
		// Stage budget: analyze the capped prefix (so an early payload still
		// matches its own rule) and append the sentinel so the overflow can
		// never hide anything — same fail-closed policy as the depth budget.
		const over = full.length > MAX_PIPELINE_STAGES;
		const p = over ? full.slice(0, MAX_PIPELINE_STAGES) : full;
		return [
			p.map((c) => c.argv).filter((argv) => argv.length),
			...p.flatMap((c, ci) => {
				const sourcePipes = scriptSources(c).map((s) => collectPipelines(s, depth + 1));
				// scriptSources lists c.subs first, then c.outSubs (see its order
				// contract), so the leading entries are the substitution pipelines
				// the syntheses need.
				const subPipes = sourcePipes.slice(0, c.subs.length);
				const outSubPipes = sourcePipes.slice(c.subs.length, c.subs.length + c.outSubs.length);
				// upstream is only consumed by the out-sub synthesis — building
				// the prefix slice unconditionally made stage cost quadratic.
				const upstream = c.outSubs.length
					? p.slice(0, ci + 1).map((x) => x.argv).filter((argv) => argv.length)
					: [];
				return [
					...sourcePipes.flat(),
					...synthesizeFetchExecPipelines(c, subPipes),
					...synthesizeOutSubPipelines(upstream, outSubPipes),
				];
			}),
			...(over ? [[[PARSE_BUDGET_SENTINEL]]] : []),
		].filter((pl) => pl.length);
	});
}
