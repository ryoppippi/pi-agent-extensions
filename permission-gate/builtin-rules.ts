/**
 * permission-gate — built-in prompt and block rules.
 *
 * Defaults are argv rules where possible: the tokenizer strips quoting,
 * env prefixes and substitutions, so `echo "sudo x"` no longer trips the
 * sudo rule while `sudo x` inside $() still does. "raw device redirect"
 * stays regex because redirect targets are not part of argv.
 *
 * `prompt` rules ask before running; `block` rules reject outright with a
 * reason for the model and stay active even when prompting is toggled off.
 */

import * as path from "node:path";
import type { ArgvPipeline, RuleEntry } from "./types.ts";
import { anyCmd, hasFlag } from "./helpers.ts";
import {
	collapseBrackets, deferredScripts, EXEC_BUILTINS, FETCHERS, hasSubPlaceholder,
	isDecoder, isSubPlaceholder, PARSE_BUDGET_SENTINEL, SHELLS,
	simpleCommands, SOURCE_BUILTINS, STDIN_RUNNERS, unwrap, unwrapSteps,
} from "./shell.ts";

// ── searchPaths (also passed to rules.ts factories) ─────────────────────

/**
 * Arguments the command treats as search paths, so patterns/flags are not
 * mistaken for paths. find: paths precede the first expression. fd/rg/grep:
 * first positional is the pattern (unless -e/-f supplies it), rest are paths.
 * Wrappers (sudo, env, timeout, …) are stripped first — see shell.ts.
 */
export function searchPaths(rawArgv: string[]): string[] {
	const [cmd, ...args] = unwrap(rawArgv);
	if (cmd === "find") return findPaths(args);
	if (cmd === "fd" || cmd === "rg" || cmd === "grep") return grepLikePaths(cmd, args);
	return [];
}

// find's grammar: paths precede the first expression. A handful of
// pre-path options must be skipped rather than break the scan — -H/-L/-P,
// -O<level>, -D <opts> and `--` are all accepted by GNU find before paths,
// and breaking on any of them hid every following path from the scan
// blocks (`find -O2 / …`, `find -- / …` matched nothing).
function findPaths(args: string[]): string[] {
	const paths: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (/^-[HLP]$/.test(arg) || /^-O/.test(arg) || arg === "--") continue;
		if (arg === "-D") { i++; continue; } // -D takes a separate value
		if (arg.startsWith("-") || arg === "(" || arg === "!") break;
		paths.push(arg);
	}
	return paths;
}

// Flags whose value arrives as a *separate* argument. Skipping the value
// keeps it from shifting positional parsing — without this, `rg -A 3 / src/`
// read "3" as the pattern and "/" as a path, and a hard block misfired on
// a legitimate search. Per-command because short letters clash (grep -E is
// boolean, rg -E takes an encoding; fd -g is boolean, rg -g takes a glob).
const VALUE_FLAGS: Record<string, RegExp> = {
	rg: /^(-[ABCEgjMmrtT]|--(after-context|before-context|context|colors|dfa-size-limit|encoding|engine|field-(context|match)-separator|glob|iglob|ignore-file|max-(columns|count|depth|filesize)|path-separator|pre|pre-glob|regex-size-limit|replace|sort|sortr|threads|type|type-add|type-clear|type-not))$/,
	grep: /^(-[ABCdDm]|--(after-context|before-context|binary-files|context|devices|directories|exclude|exclude-dir|exclude-from|group-separator|include|label|max-count))$/,
	fd: /^(-[dEjSt]|--(and|batch-size|changed-(before|within)|exact-depth|exclude|format|ignore-file|max-(buffer-time|depth|results)|min-depth|owner|path-separator|size|threads|type))$/,
};

// What one fd/rg/grep option means for path collection.
type FlagKind =
	| "pattern-with-value" // -e PAT / -f FILE: next word is the pattern, not a path
	| "pattern-inline" // -ePAT / --regexp=PAT / rg --files: no pattern positional remains
	| "path-with-value" // fd --search-path DIR: next word is a search path
	| "path-inline" // fd --search-path=DIR
	| "with-value" // -A 3: next word is an unrelated value
	| "plain"; // boolean flag / unknown option

function classifyFlag(cmd: string, arg: string): FlagKind {
	// rg --files takes no pattern at all: every positional is a path, so
	// `rg --files /` must not swallow "/" as the pattern.
	if (cmd === "rg" && arg === "--files") return "pattern-inline";
	// --base-directory changes fd's search root exactly like --search-path
	// — classifying it as an unrelated value skipped the path and
	// `fd --base-directory / pattern` walked all of / past the block.
	if (cmd === "fd" && (arg === "--search-path" || arg === "--base-directory")) return "path-with-value";
	if (cmd === "fd" && /^--(search-path|base-directory)=/.test(arg)) return "path-inline";
	if (/^(-e|-f|--regexp|--file)$/.test(arg)) return "pattern-with-value";
	// Inline pattern forms: `-efoo` / `-fpats` glue the pattern to the flag,
	// and missing them made the first positional look like the pattern — so
	// `rg -efoo /` slipped past the scan-root block.
	if (/^(--regexp|--file)=|^-[ef]./.test(arg)) return "pattern-inline";
	if (VALUE_FLAGS[cmd].test(arg)) return "with-value";
	return "plain";
}

// fd/rg/grep grammar: the first positional is the pattern (unless a
// pattern flag supplied it), every later positional is a path, and `--`
// ends option parsing. classifyFlag decides each option's effect; this
// loop only tracks whether the pattern positional is still expected.
function grepLikePaths(cmd: string, args: string[]): string[] {
	let patternSupplied = false;
	let afterDoubleDash = false;
	const positionals: string[] = [];
	// Paths supplied via value flags (fd --search-path) rather than
	// positionals — counted as search paths regardless of pattern parsing.
	const flagPaths: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const arg = args[i];
		if (afterDoubleDash || !arg.startsWith("-")) {
			positionals.push(arg);
			continue;
		}
		if (arg === "--") {
			afterDoubleDash = true;
			continue;
		}
		switch (classifyFlag(cmd, arg)) {
			case "pattern-with-value": patternSupplied = true; i++; break;
			case "pattern-inline": patternSupplied = true; break;
			case "path-with-value": if (args[i + 1] !== undefined) flagPaths.push(args[++i]); break;
			case "path-inline": flagPaths.push(arg.slice(arg.indexOf("=") + 1)); break;
			case "with-value": i++; break;
			case "plain": break;
		}
	}
	return (patternSupplied ? positionals : positionals.slice(1)).concat(flagPaths);
}

// ── prompt defaults ──────────────────────────────────────────────────────

// Git global options that consume a *separate* value — skipping only the
// flag would make the value look like the subcommand (`git --work-tree /tmp
// push -f` derailed the scan at "/tmp").
const GIT_VALUE_OPTS = new Set(["-c", "-C", "--work-tree", "--git-dir", "--namespace", "--exec-path"]);

const gitSub = (sub: string, pred?: (rest: string[]) => boolean) =>
	(p: ArgvPipeline) =>
		anyCmd(p, "git", (args) => {
			// Skip git's global -c/-C/--foo options to find the subcommand.
			let i = 0;
			while (i < args.length && args[i].startsWith("-")) {
				if (GIT_VALUE_OPTS.has(args[i])) i += 2;
				else i += 1;
			}
			return args[i] === sub && (!pred || pred(args.slice(i + 1)));
		});

// jj (Jujutsu) twin of gitSub. Global options that take a separate value
// must be skipped so their value is not mistaken for the subcommand
// (`jj -R /repo abandon`). Two-word subcommands (`op restore`) are spelled
// with a space in `sub`.
const JJ_VALUE_OPTS = new Set(["-R", "--repository", "--at-operation", "--at-op", "--config", "--config-file"]);

const jjSub = (sub: string, pred?: (rest: string[]) => boolean) =>
	(p: ArgvPipeline) =>
		anyCmd(p, "jj", (args) => {
			let i = 0;
			while (i < args.length && args[i].startsWith("-")) {
				if (JJ_VALUE_OPTS.has(args[i])) i += 2;
				else i += 1;
			}
			const words = sub.split(" ");
			return words.every((w, j) => args[i + j] === w) &&
				(!pred || pred(args.slice(i + words.length)));
		});

// Block-device name prefixes under /dev — shared by the redirect regex and
// the dd rule. disk/ (by-id/by-uuid), mapper/ (LVM/LUKS), dm-N, mdN and
// loopN write to the same disks as sdX. One list so the argv rules and the
// quote-tolerant redirect regex below can never drift apart.
const DEV_NAMES = ["sd", "hd", "vd", "xvd", "nvme", "mmcblk", "disk/", "mapper/", "dm-", "md\\d", "loop"];
const DEV_PREFIX = `(${DEV_NAMES.join("|")})`;

// The redirect rule matches the *raw* string, where bash quoting is still
// visible — and quote splices may sit at every path-segment boundary and
// between device-name characters (`> /dev/'sda'`, `> /dev/s''da`,
// `> /"dev"/sda` all name the same path; splices only between d-e-v let
// the quoted-basename spellings through). Interleave ["']* between the
// characters of each name, keeping escapes like \d as one unit.
const Q = `["']*`;
const spliceQuotes = (pattern: string) => pattern.match(/\\.|./g)!.join(Q);
const SPLICED_DEV_PREFIX = `(${DEV_NAMES.map(spliceQuotes).join("|")})`;
// A path segment of dots/quotes then a slash: absorbs `/./`, `//` and
// quote splices around either. A single character class per iteration
// (never two adjacent ["']* runs) so a long quote flood cannot trigger
// quadratic backtracking inside tool_call.
const DEV_SEG = `(["'.]*/)*`;

// Normalized-path test shared by the dd of= rule and the device-writer rule.
const DEV_PATH_RE = new RegExp(`^/dev/${DEV_PREFIX}`);
const isRawDevice = (arg: string): boolean => DEV_PATH_RE.test(path.posix.normalize(arg));

// Programs whose device-path argument means a destructive write — dd showed
// the intent, these reach the same disks without a redirect.
// dd's key=value args never look like bare /dev paths, so listing it here
// cannot double-fire with the of= rule; reads like `dd if=/dev/sda of=x`
// stay quiet for the same reason. The exotic partitioner tail (parted,
// cryptsetup, fdisk, sgdisk, …) is a documented non-goal — telling their
// read subcommands from their write ones cost per-tool tables the rare
// spellings never earned.
const DEVICE_WRITERS = new Set(["tee", "cp", "dd", "shred", "wipefs", "blkdiscard"]);

// Symbolic chmod clauses granting write to others (`a+rwx`, `o+w`,
// `ugo=rwx`) are 777-equivalents the octal check missed.
const symbolicWorldWritable = (arg: string): boolean =>
	arg.split(",").some((clause) => {
		const m = /^([ugoa]+)[+=]([rwxXst]+)$/.exec(clause);
		return !!m && /[ao]/.test(m[1]) && m[2].includes("w");
	});

// An octal mode opens the file to the world for writing when its *last*
// digit carries the write bit (2) — 666/777, but also 646, 606 and 007:
// what owner and group get is irrelevant to whether others can write
// (the symbolic twin `chmod o=rw` already matched). GNU chmod accepts any
// number of leading digits (setuid/setgid, extra zeros), so only the last
// one counts. 644/755/660 stay clean: no others-write bit.
const octalWorldWritable = (arg: string): boolean =>
	/^[0-7]{3,}$/.test(arg) && (Number.parseInt(arg[arg.length - 1], 8) & 2) !== 0;

export const DEFAULT_PROMPT_RULES: RuleEntry[] = [
	// Redirect targets aren't part of argv, so this one stays a regex — which
	// means it must absorb the spellings argv normalization would have
	// handled: the `>&`/`>|` operator forms, optional quotes around the
	// target (including `$'…'`), quote splices at every segment boundary and
	// inside every name (`/de''v/`, `/dev/'sda'`, `/"dev"/sda`) and
	// dot/duplicate-slash segments (`> "/dev/sda"`, `> /dev//sda`).
	{
		label: "raw device redirect",
		group: "device",
		pattern:
			`>[|&]?\\s*(\\$?["'])*` +
			`/${DEV_SEG}${Q}${spliceQuotes("dev")}${Q}/${DEV_SEG}${Q}` +
			SPLICED_DEV_PREFIX,
	},
	{
		// dd writes to devices via of=, not a redirect — the regex above can't see it.
		// Normalized first so dot/duplicate segments (`/dev/./sda`, `//dev//sda`)
		// still spell the same device.
		label: "raw device write (dd)",
		group: "device",
		test: (p) => anyCmd(p, "dd", (a) => a.some((x) => {
			const m = /^of=(.+)/.exec(x);
			return !!m && isRawDevice(m[1]);
		})),
	},
	{
		label: "write to raw device",
		group: "device",
		test: (p) => p.some((raw) =>
			unwrapSteps(raw).some((argv) =>
				(DEVICE_WRITERS.has(argv[0]) || argv[0].startsWith("mkfs")) &&
				argv.slice(1).some((x) => !x.startsWith("-") && isRawDevice(x)),
			),
		),
	},
	{
		label: "recursive delete",
		group: "files",
		// rsync with --delete* mirrors "remove everything not in src" onto the
		// destination — `rsync -a --delete /tmp/empty/ /x/` is the canonical
		// recursive-delete spelling outside rm/find. --del is the documented
		// alias for --delete-during.
		test: (p) => anyCmd(p, "rm", (a) => hasFlag(a, "r", "--recursive") || hasFlag(a, "R")) ||
			anyCmd(p, "rsync", (a) => a.some((x) => x === "--del" || x.startsWith("--delete"))),
	},
	{
		// find can delete/execute on its own — rm never appears at a command
		// position, so the recursive-delete rule is blind to it (-exec
		// payloads are additionally re-parsed via deferredScripts).
		label: "find -delete",
		group: "files",
		test: (p) => anyCmd(p, "find", (a) => a.includes("-delete")),
	},
	{
		// su/runuser are peers of sudo — each starts a session or command
		// with changed credentials; sudoedit is `sudo -e` under its own name.
		label: "sudo",
		group: "privilege",
		test: (p) => anyCmd(p, ["sudo", "doas", "pkexec", "su", "runuser", "sudoedit"]),
	},
	{
		label: "world-writable permissions",
		group: "files",
		test: (p) => anyCmd(p, "chmod", (a) =>
			a.some((x) => octalWorldWritable(x) || symbolicWorldWritable(x)),
		),
	},
	{
		label: "force push",
		group: "vcs",
		// A refspec starting with "+" (`git push origin +main`) forces the
		// update exactly like -f; git options never start with "+", so any
		// such argument is a refspec.
		test: gitSub("push", (a) => hasFlag(a, "f", "--force") || a.some((x) => x.startsWith("+"))),
	},
	{
		label: "delete remote branch",
		group: "vcs",
		// Force push's sibling: -d/--delete removes the remote branch, and the
		// empty-source refspec `:branch` spells the same deletion. A `:` mid-
		// refspec (`main:main`) is an ordinary push and stays clean.
		test: gitSub("push", (a) => hasFlag(a, "d", "--delete") || a.some((x) => /^:./.test(x))),
	},
	{ label: "hard reset",
		group: "vcs", test: gitSub("reset", (a) => a.includes("--hard")) },
	// jj peers of the git rules above — same blast radius, jj spelling.
	// Everyday history rewriting (squash, rebase, describe) stays clean:
	//
	// jj: local operations (abandon, restore, op restore, squash,
	// rebase, ...) are all undoable through the op log, so none of them
	// prompt. Only what escapes that safety net does: destroying op log
	// history itself, and deletions on the remote where no op log exists.
	{
		label: "jj op abandon",
		group: "vcs",
		// Discards op log entries — the recovery mechanism for every
		// other jj operation.
		test: jjSub("op abandon"),
	},
	{
		label: "jj push deletion",
		group: "vcs",
		// Deleting remote bookmarks (the jj spelling of `git push -d`); the
		// remote has no op log to restore from.
		test: jjSub("git push", (a) => hasFlag(a, "d", "--deleted") || a.includes("--delete")),
	},
	{ label: "git clean",
		group: "vcs", test: gitSub("clean", (a) => hasFlag(a, "f", "--force")) },
	{
		label: "git checkout (discard all)",
		group: "vcs",
		// `git checkout .`, the canonical `git checkout -- .`, `git checkout ./`
		// and the rev-qualified spellings (`git checkout HEAD -- .`,
		// `git checkout main .`) all discard every local change; normalize so
		// spellings of "." match. Pathspec magic `:/` / `:(top)` addresses the
		// repo root — same blast radius from any subdirectory.
		test: gitSub("checkout", (a) => {
			const isRootSpec = (x: string) =>
				x === ":/" || x === ":(top)" ||
				path.posix.normalize(x).replace(/\/+$/, "") === ".";
			const dd = a.indexOf("--");
			// Everything after `--` is a pathspec; without `--`, drop flags and
			// treat a leading non-root word as the revision (`git checkout
			// main .` discards exactly like `git checkout .`, while a lone
			// `git checkout main` is a branch switch and stays clean).
			let paths = dd !== -1 ? a.slice(dd + 1) : a.filter((x) => !x.startsWith("-"));
			if (dd === -1 && paths.length > 1 && !isRootSpec(paths[0])) paths = paths.slice(1);
			return paths.length > 0 && paths.every(isRootSpec);
		}),
	},
	{
		// Discards working-tree changes — but only when a pathspec is present;
		// bare flag invocations (`git restore --help`) restore nothing.
		label: "git restore",
		group: "vcs",
		test: gitSub("restore", (a) => a.some((x) => !x.startsWith("-"))),
	},
	{
		label: "pipe to shell",
		group: "exec",
		// producer curl/wget piped into any shell downstream. Both ends unwrap
		// so wrapper prefixes (`curl x | env sh`) can't hide the consumer, and
		// the full SHELLS set applies — dash/ksh/fish run the script just as well.
		// eval/source/. count as consumers: collectPipelines synthesizes
		// `curl … | eval` for `eval "$(curl u)"` and `curl … | source` for
		// `source <(curl u)` — source and . always execute their input.
		test: (p) => {
			const prod = p.findIndex((argv) => FETCHERS.has(unwrap(argv)[0]));
			return prod !== -1 && p.slice(prod + 1).some((argv) => {
				const head = unwrap(argv)[0];
				return SHELLS.has(head) || EXEC_BUILTINS.has(head);
			});
		},
	},
	{
		label: "glob in command name",
		group: "guard",
		// A path-spelled command containing ?/*/[…] resolves via pathname
		// expansion to whatever binary happens to match — `/usr/bin/sud? id`
		// runs sudo, and argv rules compare literal names.
		// Confirm instead of guessing the expansion. Bare relative globs in
		// *arguments* (`rm *.log`, `find … -name 'x*'`) never sit at argv[0]
		// and stay clean; single-char bracket groups are collapsed by the
		// tokenizer before this rule sees them (`/bin/r[m]` is already rm).
		test: (p) => p.some((raw) =>
			unwrapSteps(raw).some((argv) =>
				!!argv[0] && argv[0].includes("/") && /[?*[]/.test(argv[0]),
			),
		),
	},
	{
		label: "non-literal command name",
		group: "guard",
		// A command word built from expansion ($a, ${x:-rm}, sudo$x,
		// $(echo sudo)) resolves to whatever the environment says — argv
		// rules compare literal names, so every rule (blocks included) is
		// blind to it. Same treatment as the glob rule above: confirm
		// instead of guessing. Expansions at *argument* position (`echo
		// $HOME`, `ls $dir`) stay clean — and so do argument-position
		// spellings of the scan roots (`rg foo /nix/store$x`), a documented
		// limit: interpreting variable values is out of reach for a static
		// gate. A lone bare `$(…)` word is exempt — everything it does
		// lives in the separately collected substitution script, and
		// re-parsed eval/sh -c scripts spell their substitutions as bare
		// placeholders (`eval "$(git rev-parse HEAD)"` must stay clean).
		test: (p) => p.some((raw) =>
			unwrapSteps(raw).some((argv) =>
				!!argv[0] &&
				(argv[0].includes("$") || hasSubPlaceholder(argv[0])) &&
				!(argv.length === 1 && isSubPlaceholder(argv[0])),
			),
		),
	},
	{
		label: "shell executes decoded data",
		group: "exec",
		// eval / sh -c consuming a $(…)/<(…) whose pipeline contains a decoder
		// (base64 — see isDecoder) executes obfuscated code no argv rule can
		// read — collectPipelines synthesizes `decoder … | shell` for the
		// substitution spelling. Requiring the placeholder on the consumer
		// keeps this from double-firing with "shell executes stdin" on the
		// literal `base64 -d | sh` pipe; plain `$(git rev-parse HEAD)`
		// substitutions synthesize nothing.
		test: (p) => {
			const d = p.findIndex((argv) => isDecoder(argv));
			return d !== -1 && p.slice(d + 1).some((argv) => {
				const head = unwrap(argv)[0];
				return (SHELLS.has(head) || EXEC_BUILTINS.has(head)) && argv.some(hasSubPlaceholder);
			});
		},
	},
	{
		label: "shell executes stdin",
		group: "exec",
		// Any pipeline stage that is a bare shell (no -c script, no script
		// file) executes whatever arrives on its stdin — the script rides in
		// upstream as *data* (`echo 'sudo rm -rf /' | bash`, `base64 -d | sh`)
		// that no argv rule ever sees. Fetcher producers are exempt: the
		// dedicated pipe-to-shell rule already covers them. One forward pass
		// with a running upstream-fetcher flag — the per-stage prefix re-scan
		// it replaces made matching quadratic in stage count.
		test: (p) => {
			let fetcherUpstream = false;
			for (let i = 0; i < p.length; i++) {
				if (i > 0 && !fetcherUpstream && executesPipedStdin(p[i])) return true;
				if (FETCHERS.has(unwrap(p[i])[0])) fetcherUpstream = true;
			}
			return false;
		},
	},
	{
		label: "modify GitHub repo",
		group: "vcs",
		test: (p) => anyCmd(p, "gh", (a) =>
			a[0] === "repo" && ["create", "delete", "rename", "archive"].includes(a[1]),
		),
	},
	{
		label: "modify GitHub release",
		group: "vcs",
		test: (p) => anyCmd(p, "gh", (a) =>
			a[0] === "release" && ["create", "delete", "edit"].includes(a[1]),
		),
	},
	{
		// The gate's own config is the trusted layer that may disable even
		// block rules — and the gated agent's bash tool can write it
		// (`cat > …/permission-gate/rules.json`), silently neutering the gate
		// at the next reload. A regex, because redirect targets are never
		// part of argv — matchRules runs it against the raw string *and* the
		// tokenizer-decoded words, so quote splices
		// (`…/'permission-gate'/rules.json`) spell the same path. \b instead
		// of a trailing slash/dot, so spellings that stop at the directory
		// name still match — requiring the slash let both the assignment
		// spelling (`p=…/permission-gate; echo '{}' > $p/rules.json`) and the
		// cd spelling (`cd …/permission-gate && … > rules.json`) through,
		// although each must spell the directory path. Reads prompt as well
		// — rare enough to accept. Documented limits of the same
		// self-persistence class: PI_NO_GATE persisted via shell rc files,
		// and spellings that never write the path components adjacently —
		// `cd .pi && … > permission-gate.json`, or variable indirection
		// splitting the directory (`d=…/pi-agent-extensions; … >
		// $d/permission-gate/rules.json`) — catching those needs cwd and
		// variable tracking the gate does not have.
		label: "modify gate config",
		group: "guard",
		pattern: "pi-agent-extensions/permission-gate\\b|\\.pi/permission-gate\\b",
	},
	{
		// collectPipelines emits PARSE_BUDGET_SENTINEL when a parse budget
		// (nesting depth, pipeline stages) is exhausted, and unwrapSteps
		// appends it as a final step when a wrapper chain exhausts its own
		// budget — fail closed, like the brace and glob budgets. Without
		// this rule 66×`eval` or a 66-deep `$()` hid any payload from every
		// rule, blocks included. anyCmd sees both spellings: sentinel
		// pipelines and sentinel unwrap steps.
		label: "unparseable command (depth budget)",
		group: "guard",
		test: (p) => anyCmd(p, PARSE_BUDGET_SENTINEL),
	},
];

// True if this pipeline stage executes its piped stdin as shell code —
// bare shells (no -c script, no script file), GNU parallel, `.`/`source`
// on a stdin-spelled file, and xargs-fed `sh -c`. The structural half of
// the "shell executes stdin" rule; the fetcher-upstream exemption lives
// in the rule itself.
function executesPipedStdin(raw: string[]): boolean {
	const steps = unwrapSteps(raw);
	const argv = steps[steps.length - 1];
	const head = argv[0];
	// a bare `parallel` stage runs each input line as a shell command.
	if (STDIN_RUNNERS.has(head)) return true;
	// `.`/`source` execute a stdin-spelled file in the current shell
	// (`… | source /dev/stdin`) — same script-file logic as the shells below.
	if (!SHELLS.has(head) && !SOURCE_BUILTINS.has(head)) return false;
	const args = argv.slice(1);
	// -c may sit anywhere in a flag cluster (`sh -cx` ≡ `sh -xc`).
	const ci = args.findIndex((a) => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
	if (ci !== -1) {
		// xargs feeding a shell's -c turns the piped data into the executed
		// script — either the script argument is missing (xargs appends the
		// line: `… | xargs -d '\n' sh -c`) or it is the -I placeholder
		// (`… | xargs -I{} sh -c {}`). A fixed script keeps stdin as mere
		// arguments.
		const xargsStep = steps.find((s) => s[0] === "xargs");
		if (!xargsStep) return false; // plain -c: script is re-parsed
		const script = args[ci + 1];
		if (script === undefined) return true;
		const placeholders = new Set<string>();
		for (let k = 1; k < xargsStep.length; k++) {
			const a = xargsStep[k];
			if (a === "-I") placeholders.add(xargsStep[k + 1] ?? "{}");
			else if (/^-I./.test(a)) placeholders.add(a.slice(2));
			else if (a === "-i") placeholders.add("{}");
			else if (/^-i./.test(a)) placeholders.add(a.slice(2));
		}
		return placeholders.has(script);
	}
	// With -s (anywhere in a short cluster before -- / the first
	// positional) positionals are $1…, not a script file — the shell
	// still executes stdin (`bash -s -- foo`). And /dev/stdin,
	// /dev/fd/0, /proc/*/fd/0 and - are stdin spelled as a file.
	let stdinFlag = false;
	let script: string | undefined;
	for (let j = 0; j < args.length; j++) {
		const a = args[j];
		if (a === "--") { script = args[j + 1]; break; }
		if (a === "-") break; // lone dash: end of options, stdin
		if (a.startsWith("-")) {
			if (/^-[a-zA-Z]*s/.test(a)) stdinFlag = true;
			continue;
		}
		script = a;
		break;
	}
	if (script !== undefined && !stdinFlag &&
		!/^(\/dev\/stdin|\/dev\/fd\/0|\/proc\/(self|\d+)\/fd\/0|-)$/.test(script)) return false; // script file
	return true;
}

// ── block defaults ───────────────────────────────────────────────────────

const HOME = process.env.HOME;
const WHOLE_TREE_ROOTS = new Set(
	["/", "~", "$HOME", HOME].filter((v): v is string => !!v),
);
const NIX_ROOTS = new Set(["/nix", "/nix/store"]);

// `~/`, `$HOME/` -> their bare root; `/` stays `/`. Full normalization
// (collapse `//`, drop `/.` segments) so spellings like `//` or
// `/nix//store` can't slip past the exact-string root sets. A trailing
// `/*` or `/.*` glob expands to (nearly) the same tree as the bare root —
// `find /*` / `rg x /nix/store/*` must still hit the blocks.
// Single-char bracket groups collapse first so `/nix/stor[e]` spells the
// same root.
const normalizeRoot = (arg: string) => {
	const deglobbed = collapseBrackets(arg).replace(/\/\.?\*$/, "") || "/";
	const p = path.posix.normalize(deglobbed);
	return p === "/" ? p : p.replace(/\/+$/, "");
};

// A path word containing ? / * (after bracket collapsing) may still expand
// to a blocked root: `find /nix/st*re` enumerates /nix/store just the
// same. Compare glob-wise against each root in that case.
const globCouldMatchRoot = (word: string, roots: Set<string>): boolean => {
	// Only absolute glob spellings can expand to a blocked root — a relative
	// glob (`rg foo *`) expands against cwd and must stay clean.
	if (!word.startsWith("/") || !/[?*]/.test(word)) return false;
	// A glob whose static prefix ends exactly at a blocked root and whose
	// next segment is open-ended (ends in *) enumerates essentially every
	// child of the root — `rg foo /nix/store/*/bin` walks the same tree as
	// the bare root spelling. A constrained segment (`rg foo /nix/*x`)
	// names specific children, not the tree, and stays clean.
	const metaIdx = word.search(/[?*[]/);
	const prefix = word.slice(0, metaIdx);
	if (prefix.endsWith("/")) {
		const staticDir = path.posix.normalize(prefix).replace(/\/+$/, "") || "/";
		const segment = word.slice(metaIdx).split("/", 1)[0];
		if (roots.has(staticDir) && segment.endsWith("*")) return true;
	}
	// A run of * matches exactly what one * does — collapse before building
	// the regex, or N stars backtrack superlinearly against every root and
	// ~200 of them hang the gate inside tool_call…
	const collapsed = word.replace(/\*+/g, "*");
	// …and cap what's left: a pathological wildcard count fails toward
	// "could match" — blocking is the safe direction for a scan gate.
	if ((collapsed.match(/[?*]/g) ?? []).length > 8) return true;
	const rx = new RegExp(
		"^" + collapsed.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$",
	);
	return [...roots].some((root) => rx.test(root));
};

// Search paths are compared as *spelled*: cwd tracking is unavailable
// (the same pinned limit as cd-relative gate-config writes), so a
// cwd-relative scan of a blocked root (`cd / && rg foo .`) walks the same
// tree without naming it. Argument-position expansions
// (`rg foo /nix/store$x`) share the limit — both are pinned in the
// documented non-goals.
const scansRoot = (pipeline: ArgvPipeline, roots: Set<string>) =>
	pipeline.some((argv) =>
		searchPaths(argv).some((arg) => {
			const normalized = normalizeRoot(arg);
			return roots.has(normalized) || globCouldMatchRoot(normalized, roots);
		}),
	);

// `nix … <a> <b>` at any unwrap step (global flags may sit between `nix`
// and the subcommand, so match the first adjacent pair anywhere). Through
// anyCmd like every other argv rule — reading raw argv[0] made this the
// one rule any wrapper prefix (`env nix flake show`) skipped.
const isNixSubcommand = (p: ArgvPipeline, a: string, b: string) =>
	anyCmd(p, "nix", (args) => args.some((w, i) => w === a && args[i + 1] === b));

export const DEFAULT_BLOCK_RULES: RuleEntry[] = [
	{
		label: "scan /nix/store",
		group: "scan",
		action: "block",
		test: (p) => scansRoot(p, NIX_ROOTS),
		reason:
			"find/fd/rg/grep on /nix/store is blocked (millions of files). " +
			"Use nix-locate to find store paths, or inspect env vars like " +
			"$buildInputs / $NIX_CFLAGS_COMPILE / $PKG_CONFIG_PATH inside a shell.",
	},
	{
		label: "scan /",
		group: "scan",
		action: "block",
		test: (p) => scansRoot(p, WHOLE_TREE_ROOTS),
		reason:
			"find/fd/rg/grep on / or $HOME is blocked (too slow). Scope to a " +
			"subdir — depth-bounded spellings (find / -maxdepth 1, rg --max-depth 1) " +
			"are blocked with the rest; use `ls /` for a shallow listing.",
	},
	{
		label: "nix flake show",
		group: "scan",
		action: "block",
		test: (p) => isNixSubcommand(p, "flake", "show"),
		reason:
			"`nix flake show` evaluates every output and blows up on large " +
			"flakes. Use `nix eval` for specific attributes, e.g. " +
			'`nix eval .#packages.x86_64-linux --apply builtins.attrNames`.',
	},
	{
		label: "pueue head/tail",
		group: "scan",
		action: "block",
		// head/tail run *as a command* inside the task pueue executes — the
		// joined trailing args, exactly the script deferredScripts hands to
		// sh, never word-by-word (a task merely mentioning "head", like
		// `pueue add -- grep -r head src/`, must stay clean). Piping pueue's
		// own output to head/tail is fine.
		test: (p) =>
			anyCmd(p, "pueue", (a) =>
				deferredScripts(["pueue", ...a]).some((task) =>
					simpleCommands(task).some((sub) => sub[0] === "tail" || sub[0] === "head"),
				),
			),
		reason:
			"Do not head/tail inside a pueue task; it hides live output. Queue " +
			"the command without head/tail, stream it with `pueue follow`, and use " +
			"`pueue log --lines N` to view the end of the output.",
	},
];
