/**
 * permission-gate — interactive Yes/No prompt with free-text rejection reason.
 */

import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { Editor, type EditorTheme, Key, matchesKey, truncateToWidth } from "@mariozechner/pi-tui";
import { EVENTS, type GateResult } from "./types.ts";

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
			add(` ${theme.fg("text", command)}`);
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
