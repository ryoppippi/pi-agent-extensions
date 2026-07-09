/**
 * permission-gate — built-in rules and argv helpers.
 *
 * Defaults are argv rules where possible: the tokenizer strips quoting,
 * env prefixes and substitutions, so `echo "sudo x"` no longer trips the
 * sudo rule while `sudo x` inside $() still does. "raw device redirect"
 * stays regex because redirect targets are not part of argv.
 *
 * `prompt` rules ask before running; `block` rules reject outright with a
 * reason for the model and stay active even when prompting is toggled off.
 */

import type { ArgvPipeline, RuleEntry } from "./types.ts";
import { simpleCommands } from "./shell.ts";

// ── argv helpers (also passed to rules.ts factories) ─────────────────────

/**
 * Arguments the command treats as search paths, so patterns/flags are not
 * mistaken for paths. find: paths precede the first expression. fd/rg/grep:
 * first positional is the pattern (unless -e/-f supplies it), rest are paths.
 */
export function searchPaths(argv: string[]): string[] {
	const [cmd, ...args] = argv;

	if (cmd === "find") {
		const paths: string[] = [];
		for (const arg of args) {
			if (/^-[HLP]$/.test(arg)) continue; // symlink-mode flags precede paths
			if (arg.startsWith("-") || arg === "(" || arg === "!") break;
			paths.push(arg);
		}
		return paths;
	}

	if (cmd !== "fd" && cmd !== "rg" && cmd !== "grep") return [];

	// Flags that carry the pattern, so every positional arg is a path.
	const patternFlags = /^(-e|-f|--regexp(=.*)?|--file(=.*)?)$/;
	let patternFromFlag = false;
	let afterDoubleDash = false;
	const positionals: string[] = [];
	for (const arg of args) {
		if (!afterDoubleDash) {
			if (arg === "--") {
				afterDoubleDash = true;
				continue;
			}
			if (arg.startsWith("-")) {
				if (patternFlags.test(arg)) patternFromFlag = true;
				continue;
			}
		}
		positionals.push(arg);
	}
	return patternFromFlag ? positionals : positionals.slice(1);
}

/** True if any short-option cluster in args contains `letter`, or any arg equals `long`. */
function hasFlag(args: string[], letter: string, long?: string): boolean {
	return args.some((a) =>
		(long && a === long) ||
		(/^-[^-]/.test(a) && a.slice(1).includes(letter)),
	);
}

/** Match any argv in the pipeline whose program is `cmd` (or one of `cmd`). */
function anyCmd(
	pipeline: ArgvPipeline,
	cmd: string | string[],
	pred?: (args: string[]) => boolean,
): boolean {
	const names = Array.isArray(cmd) ? cmd : [cmd];
	return pipeline.some((argv) =>
		names.includes(argv[0]) && (!pred || pred(argv.slice(1))),
	);
}

// ── prompt defaults ──────────────────────────────────────────────────────

const GIT_SUB = (sub: string, pred?: (rest: string[]) => boolean) =>
	(p: ArgvPipeline) =>
		anyCmd(p, "git", (args) => {
			// Skip git's global -c/-C/--foo options to find the subcommand.
			let i = 0;
			while (i < args.length && args[i].startsWith("-")) {
				if (args[i] === "-c" || args[i] === "-C") i += 2;
				else i += 1;
			}
			return args[i] === sub && (!pred || pred(args.slice(i + 1)));
		});

export const DEFAULT_PROMPT_RULES: RuleEntry[] = [
	// Redirect targets aren't part of argv, so this one stays a regex.
	{ label: "raw device redirect", pattern: ">\\s*/dev/[sh]d[a-z]" },
	{
		label: "recursive delete",
		test: (p) => anyCmd(p, "rm", (a) => hasFlag(a, "r", "--recursive") || hasFlag(a, "R")),
	},
	{ label: "sudo", test: (p) => anyCmd(p, ["sudo", "doas"]) },
	{
		label: "world-writable permissions",
		test: (p) => anyCmd(p, "chmod", (a) => a.some((x) => /^[0-7]?777$/.test(x))),
	},
	{
		label: "force push",
		test: GIT_SUB("push", (a) => hasFlag(a, "f", "--force")),
	},
	{ label: "hard reset", test: GIT_SUB("reset", (a) => a.includes("--hard")) },
	{ label: "git clean", test: GIT_SUB("clean", (a) => hasFlag(a, "f", "--force")) },
	{
		label: "git checkout (discard all)",
		test: GIT_SUB("checkout", (a) => a.length === 1 && a[0] === "."),
	},
	{ label: "git restore", test: GIT_SUB("restore") },
	{
		label: "pipe to shell",
		// producer curl/wget piped into sh/bash anywhere downstream.
		test: (p) => {
			const prod = p.findIndex((argv) => argv[0] === "curl" || argv[0] === "wget");
			return prod !== -1 && p.slice(prod + 1).some((argv) => ["sh", "bash", "zsh"].includes(argv[0]));
		},
	},
	{
		label: "modify GitHub repo",
		test: (p) => anyCmd(p, "gh", (a) =>
			a[0] === "repo" && ["create", "delete", "rename", "archive"].includes(a[1]),
		),
	},
	{
		label: "modify GitHub release",
		test: (p) => anyCmd(p, "gh", (a) =>
			a[0] === "release" && ["create", "delete", "edit"].includes(a[1]),
		),
	},
];

// ── block defaults ───────────────────────────────────────────────────────

const HOME = process.env.HOME;
const WHOLE_TREE_ROOTS = new Set(
	["/", "~", "$HOME", HOME].filter((v): v is string => !!v),
);
const NIX_ROOTS = new Set(["/nix", "/nix/store"]);

// `~/`, `$HOME/` -> their bare root; `/` stays `/`.
const normalizeRoot = (arg: string) =>
	arg === "/" ? "/" : arg.replace(/\/+$/, "");

const scansRoot = (pipeline: ArgvPipeline, roots: Set<string>) =>
	pipeline.some((argv) =>
		searchPaths(argv).some((arg) => roots.has(normalizeRoot(arg))),
	);

// argv is `nix ... <a> <b> ...` (global flags may sit between `nix` and the
// subcommand, so match the first adjacent pair anywhere).
const isNixSubcommand = (argv: string[], a: string, b: string) =>
	argv[0] === "nix" && argv.some((w, i) => w === a && argv[i + 1] === b);

export const DEFAULT_BLOCK_RULES: RuleEntry[] = [
	{
		label: "scan /nix/store",
		action: "block",
		test: (p) => scansRoot(p, NIX_ROOTS),
		reason:
			"find/fd/rg/grep on /nix/store is blocked (millions of files). " +
			"Use nix-locate to find store paths, or inspect env vars like " +
			"$buildInputs / $NIX_CFLAGS_COMPILE / $PKG_CONFIG_PATH inside a shell.",
	},
	{
		label: "scan /",
		action: "block",
		test: (p) => scansRoot(p, WHOLE_TREE_ROOTS),
		reason:
			"find/fd/rg/grep on / or $HOME is blocked (too slow). Scope to a subdir.",
	},
	{
		label: "nix flake show",
		action: "block",
		test: (p) => p.some((argv) => isNixSubcommand(argv, "flake", "show")),
		reason:
			"`nix flake show` evaluates every output and blows up on large " +
			"flakes. Use `nix eval` for specific attributes, e.g. " +
			'`nix eval .#packages.x86_64-linux --apply builtins.attrNames`.',
	},
	{
		label: "pueue head/tail",
		action: "block",
		// head/tail inside the quoted task of `pueue add -- '... | tail'`
		// (re-parsed as shell). Piping pueue's own output to head/tail is fine.
		test: (p) =>
			anyCmd(p, "pueue", (a) =>
				a[0] === "add" &&
				a.slice(1).some((arg) =>
					simpleCommands(arg).some((sub) => sub[0] === "tail" || sub[0] === "head"),
				),
			),
		reason:
			"Do not head/tail inside a pueue task; it hides live output. Queue " +
			"the command without head/tail, stream it with `pueue follow`, and use " +
			"`pueue log --lines N` to view the end of the output.",
	},
];
