/**
 * Unit tests for the shell-analysis layers: tokenizer (tokenize.ts), argv
 * knowledge (argv.ts) and pipeline assembly (shell.ts), exercised through
 * the public shell.ts surface exactly as the rules consume it.
 *
 * Test names are the literal inputs; see rules.test.ts for the end-to-end
 * rule behaviour these primitives feed.
 *
 * Run with: bun test permission-gate
 */

import { describe, expect, test } from "bun:test";
import {
	collectPipelines, deferredScripts, MAX_PIPELINE_STAGES, MAX_UNWRAP_STEPS,
	nestedScripts, PARSE_BUDGET_SENTINEL, pipelines, simpleCommands, unwrap,
	unwrapSteps,
} from "./shell.ts";
import { table } from "./test-util.ts";

// Words must come out exactly as bash would build argv: quotes stripped,
// escapes decoded, env prefixes and comments dropped — rules compare
// literal words, so any tokenization drift is a rule bypass.
describe("simpleCommands: words, quoting and expansions", () => {
	table(simpleCommands, [
		["ls -la", [["ls", "-la"]]],
		['echo "hello world"', [["echo", "hello world"]]],
		["echo 'a b' c", [["echo", "a b", "c"]]],
		["FOO=1 BAR=2 make", [["make"]]],
		["ls # rm -rf /", [["ls"]]],
		["echo \\; x", [["echo", ";", "x"]]],
		// quoting hides structure from parsing
		['echo "a | b; c"', [["echo", "a | b; c"]]],
		["echo '$(sudo x)'", [["echo", "$(sudo x)"]]],
		['echo "$(echo \\")"', [["echo", "$(...)"], ["echo", '"']]],
		// ${VAR} normalizes to $VAR; complex expansions stay literal
		["ls ${HOME}", [["ls", "$HOME"]]],
		["ls ${HOME:-/tmp}", [["ls", "${HOME:-/tmp}"]]],
		// ANSI-C / locale quoting decode like plain quotes
		["echo $'a b'", [["echo", "a b"]]],
		["rm $'-rf' /x", [["rm", "-rf", "/x"]]],
		["echo $'\\x41\\n'", [["echo", "A\n"]]],
		['echo $"a b"', [["echo", "a b"]]],
		// simple comma brace lists expand; comma-free braces stay literal
		["{rm,-rf,/}", [["rm", "-rf", "/"]]],
		["echo file{1,2}", [["echo", "file1", "file2"]]],
		["awk '{print}' f", [["awk", "{print}", "f"]]],
		// single-char bracket groups collapse in command names only
		["/bin/r[m] -rf /", [["rm", "-rf", "/"]]],
		["echo a[b]", [["echo", "a[b]"]]],
	]);
});

// Every separator must end a simple command, and redirect targets/fd words
// are not arguments — otherwise argv words shift and rules misread them.
describe("simpleCommands: separators, pipelines and redirects", () => {
	table(simpleCommands, [
		["a; b && c || d & e", [["a"], ["b"], ["c"], ["d"], ["e"]]],
		["a | b |& c", [["a"], ["b"], ["c"]]],
		["(a; b)", [["a"], ["b"]]],
		["a\nb", [["a"], ["b"]]],
		["echo x > f", [["echo", "x"]]],
		["echo x >> f 2>&1", [["echo", "x"]]],
		["echo x >| f", [["echo", "x"]]],
		["cmd <<< 'data'", [["cmd"]]],
	]);
});

// Herestrings/heredocs aimed at a shell carry a *script*; for anyone else
// they are data — except the $(…)/`…` substitutions bash expands inside
// unquoted-delimiter bodies regardless of the receiver.
describe("simpleCommands: herestrings and heredocs", () => {
	table(simpleCommands, [
		["bash <<< 'sudo rm -rf /'", [["bash"], ["sudo", "rm", "-rf", "/"]]],
		["sh <<<'a | b'", [["sh"], ["a"], ["b"]]],
		// bash accepts the redirection before the command word
		["<<< 'sudo rm -rf /' bash", [["bash"], ["sudo", "rm", "-rf", "/"]]],
		["<<<'a | b' sh", [["sh"], ["a"], ["b"]]],
		["<<< 'sudo id' cmd", [["cmd"]]], // non-shell target: still data
		// heredoc bodies feeding non-shells stay data, following commands parse
		["cat <<EOF\nsudo rm -rf /\nEOF\nls", [["cat"], ["ls"]]],
		["cat <<'EOF'\n$(sudo x)\nEOF", [["cat"]]],
		["cat <<-EOF\n\tindented\n\tEOF\nls", [["cat"], ["ls"]]],
		// a heredoc feeding a shell is a script
		["bash <<EOF\nrm -rf /\nEOF", [["bash"], ["rm", "-rf", "/"]]],
		["sh <<'X'\nsudo id\nX", [["sh"], ["sudo", "id"]]],
		// source/. execute a stdin-spelled file — their herestrings and
		// heredocs are scripts exactly like a shell's
		["source /dev/stdin <<< 'rm -rf /'", [["source", "/dev/stdin"], ["rm", "-rf", "/"]]],
		[". /dev/stdin <<< 'sudo id'", [[".", "/dev/stdin"], ["sudo", "id"]]],
		["source /dev/stdin <<EOF\nrm -rf /\nEOF", [["source", "/dev/stdin"], ["rm", "-rf", "/"]]],
		["bash <<-EOF\n\ta | b\nEOF", [["bash"], ["a"], ["b"]]],
		// the body binds to the command carrying the <<, even when an
		// operator sits between << and the newline
		["bash <<EOF | cat\nrm -rf /\nEOF", [["bash"], ["rm", "-rf", "/"], ["cat"]]],
		["cat <<EOF && bash\nrm -rf /\nEOF", [["cat"], ["bash"]]],
		// substitutions in unquoted-delimiter bodies surface regardless of
		// receiver; quoting the delimiter (or the $ itself) suppresses them,
		// while single quotes inside the body do not
		["cat <<EOF\n$(sudo id)\nEOF", [["cat"], ["sudo", "id"]]],
		["cat <<EOF\n'$(sudo id)'\nEOF", [["cat"], ["sudo", "id"]]],
		["cat <<EOF\n\\$(sudo id)\nEOF", [["cat"]]],
		["cat <<\\EOF\n$(sudo id)\nEOF", [["cat"]]],
		// a heredoc *inside* $(…) is data too: an apostrophe, a leading `#`
		// or a `)` in the body must not open a quote, start a comment or move
		// paren depth — a desynced reader runs the substitution past its `)`
		// and every following word parses as garbage argv
		[
			"git commit -m \"$(cat <<'EOF'\nit's fine\nEOF\n)\" && ls",
			[["git", "commit", "-m", "$(...)"], ["cat"], ["ls"]],
		],
		[
			"git commit -m \"$(cat <<'EOF'\n# smiley :)\nEOF\n)\"",
			[["git", "commit", "-m", "$(...)"], ["cat"]],
		],
		// …and the body still reaches the rules when it is a script
		[
			"echo \"$(bash <<EOF\nsudo id\nEOF\n)\"",
			[["echo", "$(...)"], ["bash"], ["sudo", "id"]],
		],
	]);
});

// Substitution scripts must surface as their own commands, recursively —
// $(…) is where hidden commands live.
describe("simpleCommands: command and process substitutions", () => {
	table(simpleCommands, [
		["echo $(rm -r x)", [["echo", "$(...)"], ["rm", "-r", "x"]]],
		["echo `rm -r x`", [["echo", "$(...)"], ["rm", "-r", "x"]]],
		['echo "$(rm -r x)"', [["echo", "$(...)"], ["rm", "-r", "x"]]],
		["diff <(a) >(b)", [["diff", "<(...)", ">(...)"], ["a"], ["b"]]],
		["echo $(echo $(rm -r x))", [["echo", "$(...)"], ["echo", "$(...)"], ["rm", "-r", "x"]]],
		// arithmetic stays an opaque word, but $() inside it *does* run
		["echo $((1 + 2))", [["echo", "$((1 + 2))"]]],
		["echo $(( $(a) ))", [["echo", "$(( $(a) ))"], ["a"]]],
	]);
});

// Reserved words and grouping tokens must not bury the real command
// mid-argv — including time's -p/-- options and coproc's hidden argv[0].
describe("simpleCommands: keywords and grouping", () => {
	table(simpleCommands, [
		["if true; then a; fi", [["true"], ["a"]]],
		["for f in x y; do a; done", [["f", "in", "x", "y"], ["a"]]],
		["while a; do b; done", [["a"], ["b"]]],
		["! a", [["a"]]],
		["{ a; b; }", [["a"], ["b"]]],
		["f() { a; }", [["f"], ["a"]]],
		["function f { a; }", [["f"], ["a"]]],
		["time a", [["a"]]],
		["time -p sudo id", [["sudo", "id"]]],
		["time -- rm -rf /x", [["rm", "-rf", "/x"]]],
		["coproc rm -rf /", [["rm", "-rf", "/"]]],
		// the case *subject* is an expansion at what looks like command
		// position — dropped, while the arm commands still surface
		["case $x in a) sudo id;; esac", [["a"], ["sudo", "id"]]],
		["case \"$1\" in start) rm -rf /x;; esac", [["start"], ["rm", "-rf", "/x"]]],
	]);
});

// Path-spelled commands resolve to their basename (argv rules compare
// names); arguments never do.
describe("simpleCommands: path-spelled commands", () => {
	table(simpleCommands, [
		["/bin/rm -rf /", [["rm", "-rf", "/"]]],
		["/usr/bin/sudo id", [["sudo", "id"]]],
		["echo /bin/rm", [["echo", "/bin/rm"]]],
		["./configure --prefix=/usr", [["configure", "--prefix=/usr"]]],
	]);
});

// Inline scripts (sh -c, eval, su -c, env -S) and deferred tasks (pueue,
// tmux, find -exec) re-parse as shell so their inner commands surface.
describe("simpleCommands: inline and deferred scripts", () => {
	table(simpleCommands, [
		["bash -c 'a | b'", [["bash", "-c", "a | b"], ["a"], ["b"]]],
		["sh -lc 'a'", [["sh", "-lc", "a"], ["a"]]],
		["eval 'a; b'", [["eval", "a; b"], ["a"], ["b"]]],
		["eval a b", [["eval", "a", "b"], ["a", "b"]]],
		["su root -c 'a'", [["su", "root", "-c", "a"], ["a"]]],
		["sudo sh -c 'a'", [["sudo", "sh", "-c", "a"], ["a"]]],
		// env -S values are scripts, not option values
		["env -S 'sudo id'", [["env", "-S", "sudo id"], ["sudo", "id"]]],
		["env -S 'sudo id' extra", [["env", "-S", "sudo id", "extra"], ["sudo", "id", "extra"]]],
		["pueue add -- 'rm -rf /'", [["pueue", "add", "--", "rm -rf /"], ["rm", "-rf", "/"]]],
		["tmux new-session -d 'a | b'", [["tmux", "new-session", "-d", "a | b"], ["a"], ["b"]]],
		["find . -exec rm {} \\;", [["find", ".", "-exec", "rm", "{}", ";"], ["rm", "{}"]]],
	]);
});

// The Pipeline shape rules receive: | groups commands, substitution
// scripts attach to the command whose word carried them.
describe("pipelines", () => {
	test("groups commands connected by |", () => {
		const [p] = pipelines("a 1 | b 2 | c 3; d");
		expect(p.map((c) => c.argv)).toEqual([["a", "1"], ["b", "2"], ["c", "3"]]);
	});

	test("attaches substitution scripts to their command", () => {
		const [p] = pipelines("echo $(x) | cat");
		expect(p[0].subs).toEqual(["x"]);
		expect(p[1].subs).toEqual([]);
	});
});

// Wrapper stripping must expose the real command for every table entry —
// and must *stop* where the wrapper's argument is a script (env -S,
// runuser -c) or a query (command -v), not a wrapped argv. The table
// deliberately stops at the common wrappers; the launcher long tail is a
// documented non-goal (see rules.test.ts).
describe("unwrap", () => {
	table(unwrap, [
		[["sudo", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
		[["sudo", "-u", "alice", "ls"], ["ls"]],
		[["sudo", "--user=alice", "-E", "ls"], ["ls"]],
		[["doas", "ls"], ["ls"]],
		[["pkexec", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
		// path-spelled wrapper and wrapped command both normalize
		[["/usr/bin/sudo", "/bin/rm", "-rf", "/"], ["rm", "-rf", "/"]],
		[["env", "FOO=1", "ls"], ["ls"]],
		[["env", "-u", "PATH", "ls"], ["ls"]],
		[["env", "-", "ls"], ["ls"]],
		// env -S values are scripts — unwrapping stops so nestedScripts sees them
		[["env", "-S", "sudo id"], ["env", "-S", "sudo id"]],
		[["env", "--split-string=sudo id"], ["env", "--split-string=sudo id"]],
		[["timeout", "30", "find", "/"], ["find", "/"]],
		[["timeout", "-k", "5", "30", "find", "/"], ["find", "/"]],
		[["xargs", "rm", "-r"], ["rm", "-r"]],
		[["xargs", "-I{}", "-n", "1", "rm", "{}"], ["rm", "{}"]],
		[["nohup", "nice", "-n", "5", "make"], ["make"]],
		[["exec", "-a", "name", "cmd"], ["cmd"]],
		[["command", "git", "push"], ["git", "push"]],
		// command -v queries rather than runs — stays wrapped
		[["command", "-v", "sudo"], ["command", "-v", "sudo"]],
		[["command", "git", "log", "-v"], ["git", "log", "-v"]],
		// busybox is every applet under one name
		[["busybox", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
		[["busybox", "sh", "-c", "x"], ["sh", "-c", "x"]],
		// nix develop/shell -c wrap a trailing argv; other nix subcommands
		// (and -c-less invocations) wrap nothing and stay as-is
		[["nix", "develop", "-c", "sudo", "id"], ["id"]],
		[["nix", "develop", "--command", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
		[["nix", "shell", "nixpkgs#coreutils", "-c", "rm", "-rf", "/"], ["rm", "-rf", "/"]],
		[["nix", "develop"], ["nix", "develop"]],
		[["nix", "flake", "show"], ["nix", "flake", "show"]],
		[["nix", "run", "nixpkgs#hello"], ["nix", "run", "nixpkgs#hello"]],
		[["runuser", "-u", "root", "id"], ["id"]],
		// runuser -c is a script, not a wrapped argv — unwrapping stops so
		// nestedScripts re-parses it
		[["runuser", "root", "-c", "x"], ["runuser", "root", "-c", "x"]],
		// wrapper with no command: unchanged
		[["sudo"], ["sudo"]],
		[["sudo", "-u", "alice"], ["sudo", "-u", "alice"]],
		// not a wrapper: unchanged
		[["ls", "-la"], ["ls", "-la"]],
	]);
});

// Rules match against every step: unwrapping strips sudo/doas/pkexec
// themselves, so `env sudo id` must still expose sudo at a step.
describe("unwrapSteps", () => {
	table(unwrapSteps, [
		[["env", "sudo", "whoami"], [["env", "sudo", "whoami"], ["sudo", "whoami"], ["whoami"]]],
		[["timeout", "5", "sudo", "id"], [["timeout", "5", "sudo", "id"], ["sudo", "id"], ["id"]]],
		[["xargs", "sudo", "rm"], [["xargs", "sudo", "rm"], ["sudo", "rm"], ["rm"]]],
		// command -v queries — no intermediate step must appear
		[["command", "-v", "sudo"], [["command", "-v", "sudo"]]],
		[["ls", "-la"], [["ls", "-la"]]],
	]);
});

// Task queues, multiplexers and find -exec run their payload later, in
// another process — the returned strings are what the gate re-parses.
describe("deferredScripts", () => {
	table(deferredScripts, [
		[["pueue", "add", "--", "rm -rf /"], ["rm -rf /"]],
		[["pueue", "add", "rm", "-rf", "/tmp/x"], ["rm -rf /tmp/x"]],
		[["pueue", "add", "-g", "build", "--", "make"], ["make"]],
		[["pueue", "add"], []],
		[["pueue", "log"], []],
		// find -exec/-execdir payloads run as commands
		[["find", "/tmp/x", "-exec", "rm", "-rf", "{}", "+"], ["rm -rf {}"]],
		[["find", ".", "-execdir", "rm", "{}", ";"], ["rm {}"]],
		[["find", ".", "-name", "x"], []],
		[["tmux", "new-session", "-d", "rm -rf /"], ["rm -rf /"]],
		[["tmux", "new-window", "-n", "win", "sudo id"], ["sudo id"]],
		[["tmux", "kill-server"], []],
		[["tmux", "attach"], []],
		[["ls", "-la"], []],
	]);
});

// Inline `-c`-style scripts and eval/env -S/watch tails — the strings a
// command executes as shell code in-process.
describe("nestedScripts", () => {
	table(nestedScripts, [
		[["bash", "-c", "rm -rf /"], ["rm -rf /"]],
		[["sh", "-lc", "x"], ["x"]],
		[["zsh", "-c", "x", "arg0"], ["x"]], // trailing args are $0/$@, not scripts
		// -c anywhere in the cluster (flags combine in any order), and the
		// script is the next non-option argument
		[["bash", "-cx", "rm -rf /"], ["rm -rf /"]],
		[["sh", "-ce", "sudo id"], ["sudo id"]],
		[["bash", "-c", "-x", "rm -rf /"], ["rm -rf /"]],
		[["bash", "-c", "--", "rm -rf /"], ["rm -rf /"]],
		[["grep", "-c", "pattern", "f"], []], // grep -c counts — not a shell
		[["su", "root", "-c", "x"], ["x"]],
		[["runuser", "root", "-c", "x"], ["x"]],
		[["sg", "users", "-c", "x"], ["x"]], // su-for-groups
		[["eval", "a", "b"], ["a b"]],
		[["eval"], []],
		[["bash", "script.sh"], []], // file execution is out of scope
		[["echo", "-c", "x"], []],
		// env -S splits its value into a command line; trailing args are
		// appended by env after the split
		[["env", "-S", "sudo id"], ["sudo id"]],
		[["env", "-S", "sudo id", "extra"], ["sudo id extra"]],
		[["env", "-Ssudo id"], ["sudo id"]],
		[["env", "-u", "PATH", "-Ssudo id"], ["sudo id"]],
		[["env", "--split-string=sudo id"], ["sudo id"]],
		[["env", "-S"], []],
		[["env", "FOO=1", "ls"], []],
		// watch joins its tail and re-runs it via sh -c
		[["watch", "-n1", "sudo id"], ["sudo id"]],
		[["watch", "-n", "1", "rm -rf /tmp/x"], ["rm -rf /tmp/x"]],
		[["watch", "df", "-h"], ["df -h"]],
		[["watch", "-n1"], []],
		// trap's first operand is a script — unless it resets (-, lone
		// signal-shaped operand) or prints (-p/-l)
		[["trap", "rm -rf /", "EXIT"], ["rm -rf /"]],
		[["trap", "--", "sudo id", "EXIT"], ["sudo id"]],
		[["trap", "-", "EXIT"], []],
		[["trap", "-p"], []],
		[["trap", "-l"], []],
		[["trap", "EXIT"], []],
		[["trap", "15"], []],
		// nix-shell --run/--command values are scripts, sh -c shaped
		[["nix-shell", "--run", "rm -rf /"], ["rm -rf /"]],
		[["nix-shell", "-p", "foo", "--command", "sudo id"], ["sudo id"]],
		[["nix-shell", "shell.nix"], []],
		// git -c values of executing config keys (case-insensitive) are
		// shell scripts; everything else about the git argv is data
		[["git", "-c", "alias.co=!rm -rf /", "co"], ["rm -rf /"]],
		[["git", "-c", "core.fsmonitor=rm -rf /", "status"], ["rm -rf /"]],
		[["git", "-c", "core.pager=less -R", "-p", "log"], ["less -R"]],
		[["git", "-c", "CORE.SSHCOMMAND=ssh -i k", "fetch"], ["ssh -i k"]],
		[["git", "-c", "credential.helper=!sudo id", "pull"], ["sudo id"]],
		[["git", "-c", "credential.helper=cache", "pull"], []],
		[["git", "-c", "user.name=Me", "commit"], []],
		[["git", "-c", "alias.st=status", "st"], []],
		[["git", "commit", "-m", "x"], []],
	]);
});

// Adversarial input must exhaust a budget and degrade, never hang or
// overflow — the tool_call handler's contract is "never throw".
describe("brace expansion is work-bounded (DoS guard)", () => {
	test("adversarial group counts finish fast and fail closed", () => {
		for (const n of [20, 40, 60, 100]) {
			const word = "{a,b}".repeat(n);
			const t0 = performance.now();
			const out = simpleCommands(word);
			expect(performance.now() - t0).toBeLessThan(200);
			// over budget — argv[0] is bash's own first word (all-first
			// alternatives), never the literal brace spelling (the literal
			// bail was a gate evasion); up to 32 trailing expansions may
			// remain as harmless argument noise
			expect(out.length).toBe(1);
			expect(out[0][0]).toBe("a".repeat(n));
		}
	});

	test("budget exhaustion yields bash's first word", () => {
		expect(simpleCommands("{r,r}{m,m}{,}{,}{,}{,} -rf /x")).toEqual([["rm", "-rf", "/x"]]);
	});

	test("small expansions still work", () => {
		expect(simpleCommands("{sudo,id}")).toEqual([["sudo", "id"]]);
		expect(simpleCommands("{a,b}{c,d}")).toEqual([["ac", "ad", "bc", "bd"]]);
	});
});

// Same property for nesting depth: deep $( chains stop recursing instead
// of overflowing the stack — and exhaustion fails *closed* via the
// sentinel, so budget-deep nesting cannot hide its payload.
describe("recursion is depth-capped (DoS guard)", () => {
	test("deep $( nesting neither throws nor hangs", () => {
		const t0 = performance.now();
		expect(() => simpleCommands("$(".repeat(3500))).not.toThrow();
		expect(performance.now() - t0).toBeLessThan(5000);
	});

	const hasSentinel = (pipes: string[][][]) =>
		pipes.some((p) => p.some((argv) => argv[0] === PARSE_BUDGET_SENTINEL));

	test("depth exhaustion emits the fail-closed sentinel", () => {
		expect(hasSentinel(collectPipelines("eval ".repeat(66) + "rm -rf /"))).toBe(true);
		// simpleCommands must agree — the two walks share the budget policy
		expect(simpleCommands("eval ".repeat(66) + "rm -rf /")
			.some((argv) => argv[0] === PARSE_BUDGET_SENTINEL)).toBe(true);
	});

	test("within-budget nesting stays sentinel-free and fully parsed", () => {
		const pipes = collectPipelines("eval ".repeat(63) + "rm -rf /");
		expect(hasSentinel(pipes)).toBe(false);
		expect(pipes.some((p) => p.some((argv) => argv[0] === "rm"))).toBe(true);
	});
});

// Wrapper unwrapping shares the budget policy: each step slices a fresh
// argv, so an uncapped mechanical chain (`sudo sudo …`) ran quadratic
// inside tool_call. Past the cap the walk fails closed via a sentinel
// step; everyday chains are far below it.
describe("wrapper unwrapping is step-capped (DoS guard)", () => {
	test("a chain past the cap ends in the sentinel step", () => {
		const steps = unwrapSteps([...Array(MAX_UNWRAP_STEPS + 10).fill("sudo"), "id"]);
		expect(steps[steps.length - 1]).toEqual([PARSE_BUDGET_SENTINEL]);
		expect(steps.length).toBe(MAX_UNWRAP_STEPS + 1); // capped, not chain-length
	});

	test("within-budget chains unwrap fully, sentinel-free", () => {
		const steps = unwrapSteps([...Array(20).fill("sudo"), "id"]);
		expect(steps[steps.length - 1]).toEqual(["id"]);
		expect(steps.some((s) => s[0] === PARSE_BUDGET_SENTINEL)).toBe(false);
	});
});

// Stage count shares the budget policy: over-cap pipelines analyze the
// capped prefix and append the sentinel — fail closed, never silent —
// while everyday pipelines stay untouched.
describe("pipeline stages are budget-capped (DoS guard)", () => {
	const hasSentinel = (pipes: string[][][]) =>
		pipes.some((p) => p.some((argv) => argv[0] === PARSE_BUDGET_SENTINEL));

	test("one stage over the cap emits the sentinel, at the cap does not", () => {
		expect(hasSentinel(collectPipelines("a|".repeat(MAX_PIPELINE_STAGES) + "b"))).toBe(true);
		expect(hasSentinel(collectPipelines("a|".repeat(MAX_PIPELINE_STAGES - 1) + "b"))).toBe(false);
	});

	test("benign 30-stage pipelines parse completely, sentinel-free", () => {
		const pipes = collectPipelines("a|".repeat(30) + "b");
		expect(hasSentinel(pipes)).toBe(false);
		expect(pipes[0].length).toBe(31);
	});
});
