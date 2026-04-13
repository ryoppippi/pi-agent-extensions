/**
 * permission-gate — interactive Yes/No prompt with free-text rejection reason.
 */

import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { Editor, type EditorTheme, Key, matchesKey, truncateToWidth, wrapTextWithAnsi } from "@mariozechner/pi-tui";
import { EVENTS, type GateResult } from "./types.ts";

/** What a rule matched, shown above the command (see match.matchEvidence). */
export type MatchDetail = { label: string; evidence?: string };

/**
 * Lines of chrome the prompt needs around the command: header, evidence,
 * both options, the reason editor (reserved even while it is hidden, so
 * selecting "No" cannot reflow the block), hints, blanks — plus pi's own
 * footer. The command block is capped at whatever is left.
 *
 * The cap is the whole point: pi renders the transcript and the prompt as
 * one buffer and shows its tail, so a prompt taller than the terminal
 * scrolls its *top* out of view — exactly the header naming the rule that
 * fired. A long command must therefore lose lines, not the "why".
 */
const CHROME_LINES = 18;
const MIN_COMMAND_LINES = 3;
const MAX_COMMAND_LINES = 20;
const FALLBACK_ROWS = 24;
/** Evidence lines shown; the header still names every rule that fired. */
const MAX_EVIDENCE_LINES = 3;

/** How many display lines of the command fit without pushing out the header. */
function commandBudget(tui: unknown, evidenceLines: number): number {
	const rows = (tui as { terminal?: { rows?: number } })?.terminal?.rows ?? FALLBACK_ROWS;
	return Math.max(
		MIN_COMMAND_LINES,
		Math.min(MAX_COMMAND_LINES, rows - CHROME_LINES - evidenceLines),
	);
}

/** Hanging indent on wrapped continuations, so a wrapped line is not read
 * as another statement. */
const WRAP_INDENT = "  ";

/**
 * The command as display lines: newlines honoured, long lines wrapped
 * (never ellipsized — a truncated tail is where the dangerous argument
 * hides), the whole block capped at `budget` with a count of what was
 * dropped.
 */
export function commandLines(
	command: string,
	width: number,
	budget: number,
): { lines: string[]; hidden: number } {
	const wrapped: string[] = [];
	for (const line of command.replace(/\t/g, "  ").split("\n")) {
		// Wrapped uniformly at the narrower width: word wrapping is sequential,
		// so a wider first line cannot be mixed in without re-flowing the rest.
		const parts = wrapTextWithAnsi(line, Math.max(1, width - WRAP_INDENT.length));
		if (parts.length === 0) wrapped.push("");
		else wrapped.push(...parts.map((p, i) => (i === 0 ? p : WRAP_INDENT + p)));
	}
	if (wrapped.length <= budget) return { lines: wrapped, hidden: 0 };
	// Keep the head: it carries the program being run. The dropped tail is
	// counted, and the matched fragment is shown separately by the caller,
	// so nothing that justifies the prompt depends on the tail.
	const kept = Math.max(1, budget - 1);
	return { lines: wrapped.slice(0, kept), hidden: wrapped.length - kept };
}

/**
 * Show the review prompt. Listens for EVENTS.respond on the optional event
 * bus so external callers (e.g. Telegram) can dismiss it, and emits
 * EVENTS.waiting once that listener is armed — in that order, so even a
 * responder reacting synchronously to `waiting` cannot lose its answer.
 */
export async function showReviewPrompt(
	ctx: ExtensionContext,
	command: string,
	labels: string,
	events?: {
		on: (name: string, handler: (payload: unknown) => void) => () => void;
		emit: (name: string, payload?: unknown) => void;
	},
	matches: MatchDetail[] = [],
): Promise<GateResult> {
	return ctx.ui.custom<GateResult>((tui, theme, _kb, done_) => {
		// Unsubscribe on resolution — otherwise every prompt leaves a live
		// listener behind and one remote respond answers all past prompts.
		let offRespond: (() => void) | undefined;
		const done = (result: GateResult) => {
			offRespond?.();
			offRespond = undefined;
			done_(result);
		};
		if (events) {
			offRespond = events.on(EVENTS.respond, (payload) => {
				const p = payload as { allow?: boolean; reason?: string } | undefined;
				const allow = p?.allow === true;
				const reason = allow ? "" : (p?.reason ?? `Blocked remotely (${labels})`);
				done(allow ? { allow: true } : { allow: false, reason });
			});
			// Announce the prompt only after the respond listener exists.
			events.emit(EVENTS.waiting, { command, labels });
		}
		// Two options, no modes. The cursor starts on "Yes": the gate is a
		// confirmation layer, not a barrier, so the reflexive Enter approves.
		// Moving to "No" reveals the reason editor right there — typing is
		// optional, Enter blocks either way. Esc blocks from anywhere with no
		// input at all.
		let optionIndex = 0;
		let cachedLines: string[] | undefined;

		const editorTheme: EditorTheme = {
			borderColor: (s) => theme.fg("accent", s),
			selectList: {
				selectedPrefix: (t) => theme.fg("accent", t),
				selectedText: (t) => theme.fg("accent", t),
				description: (t) => theme.fg("muted", t),
				scrollInfo: (t) => theme.fg("dim", t),
				noMatch: (t) => theme.fg("warning", t),
			},
		};
		const editor = new Editor(tui, editorTheme);

		function refresh() {
			cachedLines = undefined;
			tui.requestRender();
		}

		editor.onSubmit = (value) => {
			const reason = value.trim()
				? `Blocked by user (${labels}): ${value.trim()}`
				: `Blocked by user (${labels})`;
			done({ allow: false, reason });
		};

		function handleInput(data: string) {
			// Esc always blocks, from either option, with no input required.
			if (matchesKey(data, Key.escape)) {
				done({ allow: false, reason: `Blocked by user (${labels})` });
				return;
			}

			if (optionIndex === 0) {
				if (matchesKey(data, Key.down)) { optionIndex = 1; refresh(); return; }
				if (matchesKey(data, Key.enter)) done({ allow: true });
				return;
			}

			// "No" selected: the editor is live. Up returns to Yes (text kept in
			// case the user comes back); everything else — including the Enter
			// that submits via editor.onSubmit — goes to the editor.
			if (matchesKey(data, Key.up)) { optionIndex = 0; refresh(); return; }
			if (matchesKey(data, Key.down)) return;
			editor.handleInput(data);
			refresh();
		}

		function render(width: number): string[] {
			if (cachedLines) return cachedLines;
			const lines: string[] = [];
			const add = (s: string) => lines.push(truncateToWidth(s, width));

			lines.push("");
			add(theme.fg("warning", " ⚠️ Dangerous command ") + theme.fg("muted", `(${labels})`));
			// What actually tripped the rule, when it is not the whole command:
			// "recursive delete" is not an answer when the rm hides on line 30.
			const evidence = matches
				.filter((m) => m.evidence && m.evidence !== command.trim())
				.slice(0, MAX_EVIDENCE_LINES);
			for (const m of evidence) {
				add(theme.fg("muted", `   ↳ ${m.label}: `) + theme.fg("warning", m.evidence!));
			}
			const cmd = commandLines(command, width - 1, commandBudget(tui, evidence.length));
			for (const line of cmd.lines) add(` ${theme.fg("text", line)}`);
			if (cmd.hidden > 0) {
				add(theme.fg("dim", ` … ${cmd.hidden} more line${cmd.hidden === 1 ? "" : "s"} (not shown)`));
			}
			lines.push("");

			const opts = ["Yes", "No"];
			for (let i = 0; i < opts.length; i++) {
				const sel = i === optionIndex;
				add(`${sel ? theme.fg("accent", " > ") : "   "}${theme.fg(sel ? "accent" : "text", opts[i])}`);
			}
			lines.push("");

			if (optionIndex === 1) {
				add(theme.fg("muted", " Reason (optional):"));
				for (const line of editor.render(width - 2)) add(` ${line}`);
				lines.push("");
				add(theme.fg("dim", " Enter block • ↑ Yes • Esc block"));
			} else {
				add(theme.fg("dim", " Enter allow • ↓ No • Esc block"));
			}
			lines.push("");

			cachedLines = lines;
			return lines;
		}

		return { render, invalidate: () => { cachedLines = undefined; }, handleInput };
	});
}
