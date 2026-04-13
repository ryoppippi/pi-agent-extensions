/**
 * Extension plumbing tests: the review prompt's event ordering, the
 * headless trust boundary and /gate persistence — exercised through
 * index.ts and ui.ts with scripted fakes (no real TUI, and config reads
 * and writes redirected to temp dirs via XDG_CONFIG_HOME).
 *
 * Run with: bun test permission-gate
 */

import { afterEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { EVENTS } from "./types.ts";
import { commandLines, showReviewPrompt } from "./ui.ts";
import { mergeUserJson } from "./config.ts";
import permissionGate from "./index.ts";

// ── fakes ────────────────────────────────────────────────────────────────

/** Minimal event bus with the on/emit surface index.ts and ui.ts use. */
function makeBus() {
	const handlers = new Map<string, Set<(p: unknown) => void>>();
	return {
		on(name: string, h: (p: unknown) => void) {
			if (!handlers.has(name)) handlers.set(name, new Set());
			handlers.get(name)!.add(h);
			return () => { handlers.get(name)?.delete(h); };
		},
		emit(name: string, payload?: unknown) {
			for (const h of [...(handlers.get(name) ?? [])]) h(payload);
		},
	};
}

/** Fake ExtensionAPI: captures event handlers and registered commands. */
function makePi() {
	const eventHandlers = new Map<string, ((event: unknown, ctx: unknown) => unknown)[]>();
	const commands = new Map<string, { handler: (args: string | undefined, ctx: unknown) => Promise<void> }>();
	const pi = {
		on(name: string, fn: (event: unknown, ctx: unknown) => unknown) {
			if (!eventHandlers.has(name)) eventHandlers.set(name, []);
			eventHandlers.get(name)!.push(fn);
		},
		events: makeBus(),
		registerCommand(name: string, def: { handler: (args: string | undefined, ctx: unknown) => Promise<void> }) {
			commands.set(name, def);
		},
	};
	const fire = async (name: string, event: unknown, ctx: unknown) => {
		let result: unknown;
		for (const fn of eventHandlers.get(name) ?? []) result = await fn(event, ctx);
		return result;
	};
	return { pi, fire, commands };
}

const fakeTheme = { fg: (_color: string, s: string) => s };
const fakeTui = { requestRender() {} };

/** A ctx whose ui.custom runs the component factory synchronously. */
const promptCtx = {
	hasUI: true,
	ui: {
		custom<T>(factory: (tui: unknown, theme: unknown, kb: unknown, done: (r: T) => void) => unknown): Promise<T> {
			return new Promise<T>((resolve) => { factory(fakeTui, fakeTheme, undefined, resolve); });
		},
	},
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
} as any;

const tempDirs: string[] = [];
const tmp = (label: string) => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), `gate-${label}-`));
	tempDirs.push(dir);
	return dir;
};
const savedEnv = {
	XDG_CONFIG_HOME: process.env.XDG_CONFIG_HOME,
	PI_NO_GATE: process.env.PI_NO_GATE,
};
const restore = (key: keyof typeof savedEnv) => {
	if (savedEnv[key] === undefined) delete process.env[key];
	else process.env[key] = savedEnv[key];
};
afterEach(() => {
	restore("XDG_CONFIG_HOME");
	restore("PI_NO_GATE");
	for (const dir of tempDirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

/** Instantiate the extension against a fake pi. PI_NO_GATE disables the
 * whole extension and is set when these tests run *inside* a gated pi
 * session — cleared here so the extension under test actually installs. */
function installGate() {
	delete process.env.PI_NO_GATE;
	const made = makePi();
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	permissionGate(made.pi as any);
	return made;
}

// The prompt must announce itself only after its respond listener exists —
// waiting-before-arming lost the answer of any responder that reacted
// synchronously (this test never settles under that ordering).
describe("review prompt event plumbing", () => {
	test("waiting fires only after the respond listener is armed", async () => {
		const bus = makeBus();
		let sawWaiting = false;
		bus.on(EVENTS.waiting, (payload) => {
			sawWaiting = true;
			expect((payload as { command: string; labels: string }).labels).toBe("sudo");
			bus.emit(EVENTS.respond, { allow: false, reason: "denied by bridge" });
		});
		const result = await showReviewPrompt(promptCtx, "sudo id", "sudo", bus);
		expect(sawWaiting).toBe(true);
		expect(result).toEqual({ allow: false, reason: "denied by bridge" });
	});

	test("a synchronous allow works the same way", async () => {
		const bus = makeBus();
		bus.on(EVENTS.waiting, () => bus.emit(EVENTS.respond, { allow: true }));
		expect(await showReviewPrompt(promptCtx, "sudo id", "sudo", bus)).toEqual({ allow: true });
	});
});

// The cursor starts on "Yes": the gate is a confirmation layer, so the
// reflexive Enter approves — blocking is one move down to "No" (or Esc
// from anywhere), and the free-text reason lives behind the third option.
describe("review prompt defaults to Yes", () => {
	type Component = { render(width: number): string[]; handleInput(data: string): void };

	const openPrompt = () => {
		let component: Component | undefined;
		const ctx = {
			hasUI: true,
			ui: {
				custom<T>(factory: (tui: unknown, theme: unknown, kb: unknown, done: (r: T) => void) => unknown): Promise<T> {
					return new Promise<T>((resolve) => {
						component = factory(fakeTui, fakeTheme, undefined, resolve) as Component;
					});
				},
			},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;
		const result = showReviewPrompt(ctx, "sudo id", "sudo");
		return { result, component: component! };
	};

	test("Enter without moving allows", async () => {
		const { result, component } = openPrompt();
		component.handleInput("\r"); // Enter on the default
		expect(await result).toEqual({ allow: true });
	});

	test("blocking is one move down to No — Enter with no text uses the generic reason", async () => {
		const { result, component } = openPrompt();
		component.handleInput("\x1b[B"); // down → No, editor appears
		component.handleInput("\r"); // Enter on the empty editor
		expect(await result).toEqual({ allow: false, reason: "Blocked by user (sudo)" });
	});

	test("Esc blocks from anywhere", async () => {
		const { result, component } = openPrompt();
		component.handleInput("\x1b"); // Esc, cursor still on Yes
		expect(await result).toEqual({ allow: false, reason: "Blocked by user (sudo)" });
	});

	test("selecting No shows the editor immediately — typing needs no extra step", async () => {
		const { result, component } = openPrompt();
		component.handleInput("\x1b[B"); // down → No, editor is live
		component.handleInput("n");
		component.handleInput("o");
		component.handleInput("\r"); // Enter blocks with the typed reason
		expect(await result).toEqual({ allow: false, reason: "Blocked by user (sudo): no" });
	});

	test("Up from No returns to Yes and Enter then allows", async () => {
		const { result, component } = openPrompt();
		component.handleInput("\x1b[B"); // down → No
		component.handleInput("\x1b[A"); // up → back to Yes
		component.handleInput("\r");
		expect(await result).toEqual({ allow: true });
	});
});

// pi renders transcript and prompt as one buffer and shows its tail, so a
// prompt taller than the terminal scrolls its own top away — and the top is
// the header naming the rule that fired. The command block therefore has a
// budget, and the fragment that tripped the rule is shown next to the label
// rather than left to be found in the command.
describe("the prompt always shows what it is blocking about", () => {
	type Component = { render(width: number): string[]; handleInput(data: string): void };

	const renderPrompt = (
		command: string,
		matches: { label: string; evidence?: string }[] = [],
		rows = 24,
		width = 80,
	) => {
		let component: Component | undefined;
		const tui = { requestRender() {}, terminal: { rows, columns: width } };
		const ctx = {
			hasUI: true,
			ui: {
				custom<T>(factory: (t: unknown, theme: unknown, kb: unknown, done: (r: T) => void) => unknown): Promise<T> {
					return new Promise<T>((resolve) => {
						component = factory(tui, fakeTheme, undefined, resolve) as Component;
					});
				},
			},
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
		} as any;
		void showReviewPrompt(ctx, command, matches.map((m) => m.label).join(", ") || "sudo", undefined, matches);
		return { component: component!, lines: component!.render(width) };
	};

	test("a 200-line command still fits on screen, header first", () => {
		const command = Array.from({ length: 200 }, (_, i) => `line ${i}`).join("\n");
		const { component, lines } = renderPrompt(command, [{ label: "sudo" }]);
		expect(lines.length).toBeLessThanOrEqual(24);
		expect(lines[1]).toContain("Dangerous command");
		expect(lines.join("\n")).toContain("more lines (not shown)");
		// The reason editor must not push the header off either.
		component.handleInput("\x1b[B"); // down → No, editor appears
		const withEditor = component.render(80);
		expect(withEditor.length).toBeLessThanOrEqual(24);
		expect(withEditor[1]).toContain("Dangerous command");
	});

	test("a short command is shown in full, on its own lines", () => {
		const { lines } = renderPrompt("git push --force\ngit clean -fdx", [{ label: "force push" }]);
		expect(lines.some((l) => l.includes("git push --force"))).toBe(true);
		expect(lines.some((l) => l.includes("git clean -fdx"))).toBe(true);
		expect(lines.join("\n")).not.toContain("more lines");
	});

	test("the matched fragment is named next to the rule", () => {
		const command = `python3 - <<'PY'\n${"x = 1\n".repeat(50)}PY`;
		const { lines } = renderPrompt(command, [{ label: "recursive delete", evidence: "rm -rf /srv/data" }]);
		expect(lines[2]).toContain("recursive delete");
		expect(lines[2]).toContain("rm -rf /srv/data");
	});

	test("the fragment is dropped when it is the whole command", () => {
		const { lines } = renderPrompt("sudo id", [{ label: "sudo", evidence: "sudo id" }]);
		expect(lines.filter((l) => l.includes("sudo id")).length).toBe(1);
	});

	// Ellipsizing a long line hides the tail — which is where the dangerous
	// argument (the path being deleted, the host being pushed to) lives.
	test("long lines wrap instead of being cut off", () => {
		const command = `rm -rf ${"a".repeat(100)}/data`;
		const { lines } = commandLines(command, 40, 10);
		expect(lines.length).toBeGreaterThan(1);
		expect(lines.join("")).toContain("/data");
		for (const line of lines) expect(line.length).toBeLessThanOrEqual(40);
	});

	test("the budget counts display lines, not source lines", () => {
		const command = Array.from({ length: 5 }, () => "b".repeat(100)).join("\n");
		const { lines, hidden } = commandLines(command, 22, 6);
		expect(lines.length).toBe(5);
		expect(hidden).toBe(20); // 5 source lines × 5 display lines each, minus 5 kept
	});
});

// PI_NO_GATE is the documented kill switch — set to 1 to disable the gate
// (prompts and block rules). Only the exact value "1" counts: treating
// any non-empty value as a disable made PI_NO_GATE=0 turn the gate off.
describe("PI_NO_GATE kill switch", () => {
	const fireSudo = (made: ReturnType<typeof makePi>) =>
		made.fire(
			"tool_call",
			{ toolName: "bash", input: { command: "sudo id" } },
			{ hasUI: false, cwd: tmp("nogate") },
		);

	test("PI_NO_GATE=1 disables the gate entirely", async () => {
		process.env.PI_NO_GATE = "1";
		const made = makePi();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		permissionGate(made.pi as any);
		expect(await fireSudo(made)).toBeUndefined(); // no handlers installed
	});

	test("PI_NO_GATE=0 leaves the gate active", async () => {
		process.env.PI_NO_GATE = "0";
		const made = makePi();
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		permissionGate(made.pi as any);
		expect(await fireSudo(made)).toEqual({
			block: true,
			reason: expect.stringContaining("sudo"),
		});
	});
});

// .pi/permission-gate.json may not neuter prompt rules when there is no UI:
// headless prompts hard-block, so a repo-shipped disable would escalate
// "blocked" to "runs with zero record". The refusal goes to stderr — the
// only warn channel a headless session has.
describe("headless trust boundary (end to end)", () => {
	test("project disabledRules cannot remove prompt rules without a UI", async () => {
		process.env.XDG_CONFIG_HOME = tmp("xdg"); // isolate user-scope config
		const cwd = tmp("proj");
		fs.mkdirSync(path.join(cwd, ".pi"));
		fs.writeFileSync(
			path.join(cwd, ".pi", "permission-gate.json"),
			JSON.stringify({ disabledRules: ["sudo"] }),
		);
		const { fire } = installGate();
		const errors: string[] = [];
		const orig = console.error;
		console.error = (msg: unknown) => { errors.push(String(msg)); };
		try {
			await fire("session_start", {}, { hasUI: false, cwd });
		} finally {
			console.error = orig;
		}
		expect(errors.some((m) => m.includes("may not disable prompt rule(s) without a UI") && m.includes("sudo"))).toBe(true);
		// The sudo rule survived: headless the command hard-blocks as always.
		const res = await fire(
			"tool_call",
			{ toolName: "bash", input: { command: "sudo id" } },
			{ hasUI: false, cwd },
		);
		expect(res).toEqual({ block: true, reason: expect.stringContaining("sudo") });
	});
});

// /gate add|rm re-serialize rules.json — unknown keys a hand-edited file
// carries must survive the round-trip, and a label collision with a
// built-in must splice the user's rule, not disable the built-in.
describe("user rules.json persistence (/gate add|rm)", () => {
	test("mergeUserJson preserves unknown keys", () => {
		const merged = mergeUserJson(
			{ extraRules: [{ label: "old", pattern: "o" }], comment: "keep me", $schema: "x" },
			{ extraRules: [{ label: "new", pattern: "n" }] },
		);
		expect(merged.comment).toBe("keep me");
		expect(merged.$schema).toBe("x");
		expect(merged.extraRules).toEqual([{ label: "new", pattern: "n" }]);
	});

	test("mergeUserJson degrades malformed raw shapes to the sanitized view", () => {
		expect(mergeUserJson(null, { disabledRules: ["x"] })).toEqual({ disabledRules: ["x"] });
		expect(mergeUserJson([1, 2], {})).toEqual({});
		expect(mergeUserJson("junk", { extraRules: [] })).toEqual({ extraRules: [] });
	});

	test("/gate rm splices the user-json rule when a built-in shares its label", async () => {
		const configHome = tmp("xdg");
		process.env.XDG_CONFIG_HOME = configHome;
		const gateDir = path.join(configHome, "pi-agent-extensions", "permission-gate");
		fs.mkdirSync(gateDir, { recursive: true });
		fs.writeFileSync(
			path.join(gateDir, "rules.json"),
			JSON.stringify({
				extraRules: [{ label: "sudo", pattern: "sudo-ish" }],
				myNote: "hand-edited", // unknown key: must survive the round-trip
			}),
		);
		const cwd = tmp("proj");
		const { fire, commands } = installGate();
		const ctx = {
			hasUI: true,
			cwd,
			ui: {
				notify() {},
				setStatus() {},
				theme: fakeTheme,
				select: async () => "sudo",
				input: async () => "",
			},
		};
		await fire("session_start", {}, ctx);
		await commands.get("gate")!.handler("rm", ctx);
		const saved = JSON.parse(fs.readFileSync(path.join(gateDir, "rules.json"), "utf-8"));
		expect(saved.extraRules).toEqual([]); // the user's own rule was spliced…
		expect(saved.disabledRules ?? []).not.toContain("sudo"); // …not the built-in disabled
		expect(saved.myNote).toBe("hand-edited");
	});
});
