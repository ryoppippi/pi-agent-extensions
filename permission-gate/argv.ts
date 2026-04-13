/**
 * permission-gate — argv-level knowledge about programs.
 *
 * Two kinds of knowledge live here:
 *
 *   - Wrapper unwrapping (`WRAPPERS`, `unwrapSteps`, `unwrap`): strips
 *     launcher prefixes (sudo, env, timeout, …) so argv[0] is the real
 *     command; every intermediate step is kept for rules to inspect.
 *   - Executor knowledge (`nestedScripts`, `deferredScripts`, `SHELLS`,
 *     `STDIN_RUNNERS`, `FETCHERS`, `isDecoder`): which argvs carry shell
 *     code to run — inline (`sh -c`), or handed to another process
 *     (pueue, tmux, find -exec) — and which programs produce content a
 *     downstream shell would execute.
 *
 * tokenize.ts produces the words these functions inspect; shell.ts
 * composes both layers into pipeline traversal.
 */

import { collapseBrackets, PARSE_BUDGET_SENTINEL } from "./tokenize.ts";

/** Mutable per-unwrap parsing state handed to a wrapper's onArg. */
interface WrapperArgState {
	/** Leading positional arguments still owned by the wrapper. */
	positionals: number;
	/** Scratch for subcommand-shaped wrappers (nix): the subcommand seen. */
	sub?: string;
	/** Scratch: the next argument starts the wrapped command. */
	execNext?: boolean;
}

/** How unwrapSteps handles one wrapper program's own arguments. */
interface Wrapper {
	/** Options that consume a separate value word (`sudo -u alice …`). */
	valueOpts: Set<string>;
	/** Leading non-option arguments that belong to the wrapper itself
	 * (timeout's duration, runuser's user). */
	skipPositionals?: number;
	/**
	 * Wrapper-specific argument handling, consulted before the generic
	 * option rules — all per-wrapper knowledge lives in this table, never
	 * in the unwrapSteps loop. Return "stop" when the wrapper is not
	 * wrapping a plain argv after all (e.g. the option value is a shell
	 * script — nestedScripts re-parses it), "skip" to consume this single
	 * word, or undefined to fall through. May mutate `state` for options
	 * that change how many positionals the wrapper owns or that mark where
	 * the wrapped command begins.
	 */
	onArg?: (arg: string, state: WrapperArgState) => "stop" | "skip" | undefined;
}

/**
 * Wrapper programs that run another command given as their trailing
 * arguments. Unwrapped before matching so `sudo rm -rf /` still counts as
 * `rm` and `timeout 30 find / …` still counts as `find`.
 *
 * Deliberately only the common wrappers. Anything absent from this table
 * shields whatever follows it (`valgrind rm -rf /` matches nothing), but
 * the launcher long tail — debuggers, sandboxes, cpu/io shapers, the
 * dynamic loader, chroot and friends — is not worth the table it takes: a
 * syntax gate cannot enumerate launchers, so the tail is pinned as a
 * documented non-goal instead.
 */
const WRAPPERS: Record<string, Wrapper> = {
	sudo: { valueOpts: new Set(["-u", "-g", "-p", "-h", "-C", "-D", "-R", "-T", "-U"]) },
	doas: { valueOpts: new Set(["-u"]) },
	pkexec: { valueOpts: new Set(["--user"]) },
	env: {
		valueOpts: new Set(["-u", "-C", "--unset", "--chdir"]),
		// -S/--split-string re-splits its value into a whole command line —
		// a *script*, not a wrapped argv. Consuming it as an option value
		// would swallow the command entirely (`env -S 'sudo rm -rf /'`
		// matched nothing): stop unwrapping so nestedScripts re-parses it.
		// VAR=value assignments are env's own arguments — skip them.
		onArg: (arg) =>
			/^(-S|--split-string)/.test(arg) ? "stop"
			: /^[A-Za-z_][A-Za-z0-9_]*=/.test(arg) ? "skip"
			: undefined,
	},
	// `command -v foo` queries whether foo exists rather than running it —
	// don't unwrap, or the query would prompt like the real command.
	command: {
		valueOpts: new Set(),
		onArg: (arg) => (/^-[a-zA-Z]*[vV]/.test(arg) ? "stop" : undefined),
	},
	builtin: { valueOpts: new Set() },
	exec: { valueOpts: new Set(["-a"]) },
	nohup: { valueOpts: new Set() },
	nice: { valueOpts: new Set(["-n", "--adjustment"]) },
	stdbuf: { valueOpts: new Set(["-i", "-o", "-e"]) },
	time: { valueOpts: new Set() },
	timeout: { valueOpts: new Set(["-k", "--kill-after", "-s", "--signal"]), skipPositionals: 1 },
	xargs: { valueOpts: new Set(["-a", "-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s"]) },
	setsid: { valueOpts: new Set() },
	runuser: {
		valueOpts: new Set(["-u", "--user", "-g", "--group", "-G", "--supp-group"]),
		skipPositionals: 1,
		// -c '…' is a script (same shape as env -S: stop unwrapping and let
		// nestedScripts re-parse it). With -u the command follows directly —
		// no user positional — so the skip is zeroed, or `runuser -u root
		// rm …` would swallow rm as the "user".
		onArg: (arg, state) => {
			if (/^(-c$|--command)/.test(arg)) return "stop";
			if (arg === "-u" || arg === "--user") state.positionals = 0;
			return undefined;
		},
	},
	// busybox is every applet under one name: dropping the "busybox" word
	// leaves applet-as-argv[0], so `busybox rm -rf /` matches the rm rule
	// and `busybox sh -c '…'` re-parses via nestedScripts.
	busybox: { valueOpts: new Set() },
	// `nix develop -c CMD…` / `nix shell …#pkg -c CMD…` run CMD as a wrapped
	// argv inside the dev/shell environment. Everything before -c/--command
	// (subcommand, installables, flags) belongs to nix; other nix
	// subcommands wrap nothing, so consuming every argument leaves "wrapper
	// with no command" and the argv stays as-is (`nix flake show` keeps
	// matching its own rule).
	nix: {
		valueOpts: new Set(),
		onArg: (arg, state) => {
			if (state.execNext) return undefined; // the wrapped command starts here
			if (state.sub === undefined && !arg.startsWith("-")) state.sub = arg;
			else if ((state.sub === "develop" || state.sub === "shell") &&
				(arg === "-c" || arg === "--command")) state.execNext = true;
			return "skip";
		},
	},
};

// argv[0] spelled as a path still runs the same program: /bin/rm is rm.
// Rules compare command names, so keep them from being dodged that way.
export const basenameCmd = (word: string): string => {
	const w = collapseBrackets(word);
	const i = w.lastIndexOf("/");
	if (i === -1 || i === w.length - 1) return w;
	const base = w.slice(i + 1);
	// A glob left in the basename means pathname expansion picks the binary
	// (`/usr/bin/sud?`) — keep the full spelling so the "glob in command
	// name" rule can see path + glob together.
	return /[?*[]/.test(base) ? w : base;
};

/**
 * Budget on unwrap steps. Every step slices a fresh argv, so cost is
 * steps × words — unbudgeted, wrapper unwrapping was the one walk without
 * a cap and a mechanical 20k-word `sudo sudo …` chain ran quadratic
 * (~12 s) inside tool_call while brace/depth/stage/glob budgets all held.
 * 64 is far beyond any legitimate wrapper chain; exhaustion fails closed
 * via a sentinel step, matched by the "unparseable command" rule through
 * anyCmd like the depth and stage budgets.
 */
export const MAX_UNWRAP_STEPS = 64;

/**
 * Every argv seen while stripping wrapper programs, outermost first: the
 * raw (basename-normalized) argv, each intermediate step, and the fully
 * unwrapped result. Rules must consider *all* steps, not just the last —
 * unwrapping strips sudo/doas/pkexec themselves, so `env sudo id` never
 * shows sudo at argv[0] of the final step and a final-only match would
 * let any wrapper prefix hide privilege escalation.
 *
 * Memoized per argv array: every argv rule re-walks the same pipeline
 * argvs through anyCmd, so one computation serves the whole matchRules
 * call (argv arrays are never mutated after parsing).
 */
const unwrapStepsCache = new WeakMap<string[], string[][]>();

export function unwrapSteps(argv: string[]): string[][] {
	const cached = unwrapStepsCache.get(argv);
	if (cached) return cached;
	const steps = computeUnwrapSteps(argv);
	unwrapStepsCache.set(argv, steps);
	return steps;
}

function computeUnwrapSteps(argv: string[]): string[][] {
	const steps: string[][] = [];
	let rest = argv;
	for (;;) {
		// A wrapper's command argument may itself be a path (`sudo /bin/rm`).
		if (rest.length && basenameCmd(rest[0]) !== rest[0]) {
			rest = [basenameCmd(rest[0]), ...rest.slice(1)];
		}
		steps.push(rest);
		const wrapper = WRAPPERS[rest[0]];
		if (!wrapper) return steps;
		if (steps.length >= MAX_UNWRAP_STEPS) {
			// Still more to unwrap with the budget spent: fail closed (see
			// MAX_UNWRAP_STEPS) — silently stopping would hide the payload
			// exactly like the depth budget once did.
			steps.push([PARSE_BUDGET_SENTINEL]);
			return steps;
		}
		let i = 1;
		const state: WrapperArgState = { positionals: wrapper.skipPositionals ?? 0 };
		while (i < rest.length) {
			const arg = rest[i];
			const verdict = wrapper.onArg?.(arg, state);
			if (verdict === "stop") return steps;
			if (verdict === "skip") { i += 1; continue; }
			if (wrapper.valueOpts.has(arg)) i += 2; // option with separate value
			else if (arg.startsWith("-")) i += 1; // flag, --opt=value, or lone "-" (env -)
			else if (state.positionals > 0) { state.positionals--; i += 1; }
			else break;
		}
		if (i >= rest.length) return steps; // wrapper with no command
		rest = rest.slice(i);
	}
}

/** Strip leading wrapper programs (sudo, env, xargs, …) so argv[0] is the real command. */
export function unwrap(argv: string[]): string[] {
	const steps = unwrapSteps(argv);
	return steps[steps.length - 1];
}

/** Programs that execute shell code — used for `-c` scripts, herestring
 * scripts and the pipe-to-shell rule, so one list stays authoritative. */
export const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "mksh", "fish"]);

/** Builtins that read and execute a *file* (or stdin spelled as a file) in
 * the current shell. Unlike eval they always execute their input — used
 * wherever a shell's stdin/herestring/heredoc counts as a script. */
export const SOURCE_BUILTINS = new Set([".", "source"]);

/** Builtins that execute their input as shell code: eval re-parses its
 * arguments, `.`/`source` execute the attached file. The consumer side of
 * every fetch/decode-and-execute correlation — missing from any one of
 * them, `source <(curl …)` ran with no rule match while the `bash`
 * spelling of the same command was gated. */
export const EXEC_BUILTINS = new Set(["eval", ...SOURCE_BUILTINS]);

/** Non-shell programs that run their stdin as shell commands — GNU
 * parallel runs each input line through one. Shared by pipelines()
 * (herestring/heredoc receivers) and the "shell executes stdin" rule so
 * the pipe and redirect spellings can never disagree. */
export const STDIN_RUNNERS = new Set(["parallel"]);

/** Programs that fetch remote content — the producer side of the
 * pipe-to-shell rule and its `bash <(curl …)` synthesis. One list so the
 * rule and the synthesis can never disagree about what counts as a
 * fetcher. Only curl and wget: the exotic droppers (nc, socat, aria2c,
 * ftp, …) are documented non-goals. */
export const FETCHERS = new Set(["curl", "wget"]);

/** True if this argv decodes obfuscated data — the producer side of the
 * decode-and-execute correlation, shared by the substitution synthesis
 * and the "shell executes decoded data" rule so they can never disagree.
 * base64 is the one modeled decoder; the rest of the decoder zoo (xxd,
 * zcat, gpg -d, openssl …) is a documented non-goal. */
export function isDecoder(rawArgv: string[]): boolean {
	return unwrap(rawArgv)[0] === "base64";
}

// tmux subcommands whose trailing arguments are run as a shell command.
const TMUX_RUN_CMDS = new Set([
	"new-session", "new",
	"new-window", "neww",
	"split-window", "splitw",
	"run-shell", "run",
]);

/**
 * Shell code this command hands to *another* process to execute later
 * (task queues, terminal multiplexers). Without this the gate only sees
 * the launcher's argv and every rule is blind to the actual task — e.g.
 * `pueue add -- 'rm -rf /'` matches nothing but the head/tail rule.
 * Expects unwrapped argv; callers re-parse the results via `pipelines()`.
 */
export function deferredScripts(argv: string[]): string[] {
	if (argv[0] === "pueue" && argv[1] === "add") {
		// pueue joins its trailing args into one string and runs it via sh.
		const valueOpts = new Set([
			"-w", "--working-directory", "-d", "--delay", "-g", "--group",
			"-l", "--label", "-p", "--priority", "-a", "--after",
		]);
		let i = 2;
		while (i < argv.length) {
			if (argv[i] === "--") { i++; break; }
			if (valueOpts.has(argv[i])) { i += 2; continue; }
			if (argv[i].startsWith("-")) { i++; continue; }
			break;
		}
		const task = argv.slice(i).join(" ");
		return task ? [task] : [];
	}
	if (argv[0] === "find") {
		// -exec/-execdir (and the prompting -ok variants) run their payload as
		// a command; surface it (joined up to the ;/+ terminator) so rules see
		// e.g. `find x -exec rm -rf {} +` as a recursive delete.
		const scripts: string[] = [];
		for (let i = 1; i < argv.length; i++) {
			if (!/^-(exec|execdir|ok|okdir)$/.test(argv[i])) continue;
			const words: string[] = [];
			let j = i + 1;
			for (; j < argv.length && argv[j] !== ";" && argv[j] !== "+"; j++) words.push(argv[j]);
			if (words.length) scripts.push(words.join(" "));
			i = j;
		}
		return scripts;
	}
	if (argv[0] === "tmux") {
		const sub = argv.findIndex((a) => TMUX_RUN_CMDS.has(a));
		if (sub === -1) return [];
		const valueOpts = new Set(["-s", "-t", "-n", "-c", "-e", "-f", "-F", "-x", "-y"]);
		const words: string[] = [];
		for (let i = sub + 1; i < argv.length; i++) {
			if (valueOpts.has(argv[i])) { i++; continue; }
			if (argv[i].startsWith("-")) continue;
			words.push(argv[i]);
		}
		return words.length ? [words.join(" ")] : [];
	}
	return [];
}

// git config keys whose value is a shell command executed as-is (no `!`
// marker needed) — see the git branch of nestedScripts. Lower-case:
// git compares section and variable names case-insensitively.
const GIT_EXEC_CONFIG_KEYS = new Set(["core.fsmonitor", "core.pager", "core.sshcommand"]);

/**
 * Inline scripts this command executes as shell code: `sh -c '…'`
 * (also `bash -lc`), `su … -c '…'`, `eval …`. Callers re-parse these via
 * `pipelines()` so rules see the inner commands. Expects unwrapped argv.
 */
export function nestedScripts(argv: string[]): string[] {
	if (argv[0] === "eval") return argv.length > 1 ? [argv.slice(1).join(" ")] : [];
	// `trap 'CMD' EXIT` re-parses CMD when the signal fires — and EXIT fires
	// the moment the tool call's bash exits, so the payload is not deferred
	// in any meaningful sense. `-l`/`-p` list/print, a `-` action or a lone
	// signal-shaped operand resets — none of those executes anything.
	if (argv[0] === "trap") {
		let i = 1;
		while (i < argv.length && argv[i].startsWith("-") && argv[i] !== "-" && argv[i] !== "--") {
			if (/[lp]/.test(argv[i])) return []; // -l lists signals, -p prints traps
			i++;
		}
		if (argv[i] === "--") i++;
		const action = argv[i];
		if (action === undefined || action === "-") return [];
		// `trap EXIT` / `trap 15`: a single signal-shaped operand resets.
		if (i === argv.length - 1 && /^([0-9]+|(SIG)?[A-Z][A-Z0-9+_-]*)$/.test(action)) return [];
		return [action];
	}
	// nix-shell --run/--command '…' executes the string via the interactive
	// shell once the environment is built — sh -c shaped, not wrapper shaped.
	if (argv[0] === "nix-shell") {
		const scripts: string[] = [];
		for (let i = 1; i < argv.length; i++) {
			if ((argv[i] === "--run" || argv[i] === "--command") && argv[i + 1] !== undefined) {
				scripts.push(argv[++i]);
			}
		}
		return scripts;
	}
	// procps `watch` joins its trailing arguments and re-runs them via
	// `sh -c` every interval — the tail is a script, not a wrapped argv.
	if (argv[0] === "watch") {
		const words: string[] = [];
		for (let i = 1; i < argv.length; i++) {
			const a = argv[i];
			if (!words.length && a.startsWith("-")) {
				if (a === "-n" || a === "--interval") i++; // value option
				continue;
			}
			words.push(a);
		}
		return words.length ? [words.join(" ")] : [];
	}
	// GNU env -S: the string is split into a command line and executed —
	// unwrapSteps stops there (see its comment), so argv[0] is still "env".
	// Trailing arguments are appended by env after splitting, hence the join.
	if (argv[0] === "env") {
		for (let i = 1; i < argv.length; i++) {
			const a = argv[i];
			if (a === "-S" || a === "--split-string") {
				return argv[i + 1] === undefined ? [] : [[argv[i + 1], ...argv.slice(i + 2)].join(" ")];
			}
			if (a.startsWith("--split-string=")) {
				return [[a.slice("--split-string=".length), ...argv.slice(i + 1)].join(" ")];
			}
			if (a.startsWith("-S") && a.length > 2) {
				return [[a.slice(2), ...argv.slice(i + 1)].join(" ")];
			}
			// Same option list as the wrapper table, so the two parsers cannot drift.
			if (WRAPPERS.env.valueOpts.has(a)) { i++; continue; }
			if (a.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(a)) continue;
			break; // a command word: plain env, unwrapSteps would have stripped it
		}
		return [];
	}
	// git -c name=value sets any config for one invocation, and several
	// keys' values are *shell commands* git runs: alias.X=!… (via sh, the
	// moment the alias is invoked), core.fsmonitor (on a plain `git
	// status`), core.pager (whenever output pages), core.sshCommand (any
	// ssh transport), credential.helper=!… (when credentials are needed).
	// The payload sits at argument position of a "benign" git invocation,
	// so `git -c 'alias.co=!rm -rf /' co` matched nothing until the value
	// was re-parsed. Non-executing keys (user.name, core.editor, …) stay
	// data. git rejects a sticked `-cx=y` spelling, so only the
	// separate-word form needs parsing. git gets this treatment because it
	// is *the* agent tool; the same channel in other programs (tar
	// --to-command, rsync -e, sed's e-command, …) is a documented non-goal.
	if (argv[0] === "git") {
		const scripts: string[] = [];
		for (let i = 1; i < argv.length; i++) {
			if (argv[i] !== "-c" || argv[i + 1] === undefined) continue;
			const kv = argv[++i];
			const eq = kv.indexOf("=");
			if (eq === -1) continue;
			// Section and variable names are case-insensitive to git.
			const key = kv.slice(0, eq).toLowerCase();
			const value = kv.slice(eq + 1);
			if (key.startsWith("alias.") || key === "credential.helper") {
				// A leading ! means "run through the shell"; without it the
				// value is a git subcommand / helper name, not a script.
				if (value.startsWith("!")) scripts.push(value.slice(1));
			} else if (GIT_EXEC_CONFIG_KEYS.has(key) && value) {
				scripts.push(value);
			}
		}
		return scripts;
	}
	// `sg` is su-for-groups — its -c script is a peer of `su -c`.
	if (SHELLS.has(argv[0]) || argv[0] === "su" || argv[0] === "runuser" || argv[0] === "sg") {
		// The cluster may carry letters after the c too (`bash -cx '…'` ≡
		// `bash -xc '…'` — flags combine in any order), and the script is the
		// next non-option argument, not necessarily the very next word
		// (`bash -c -x 'rm -rf /'` runs rm).
		const ci = argv.findIndex((a, idx) => idx > 0 && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
		if (ci !== -1) {
			for (let j = ci + 1; j < argv.length; j++) {
				if (argv[j] === "--" || argv[j] === "-") {
					return argv[j + 1] !== undefined ? [argv[j + 1]] : [];
				}
				if (!argv[j].startsWith("-")) return [argv[j]];
			}
		}
	}
	return [];
}
