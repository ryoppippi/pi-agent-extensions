/**
 * permission-gate — interactive Yes/No prompt with free-text rejection reason.
 */

import type { ExtensionContext } from "@mariozechner/pi-coding-agent";
import { Editor, type EditorTheme, Key, matchesKey, truncateToWidth } from "@mariozechner/pi-tui";
import type { GateResult } from "./types.ts";

/**
 * Show the review prompt. Also listens for `permission-gate:respond` on the
 * optional event bus so external callers (e.g. Telegram) can dismiss it.
 */
export async function showReviewPrompt(
	ctx: ExtensionContext,
	command: string,
	labels: string,
	events?: { on: (name: string, handler: (payload: unknown) => void) => unknown },
): Promise<GateResult> {
	return ctx.ui.custom<GateResult>((tui, theme, _kb, done) => {
		if (events) {
			events.on("permission-gate:respond", (payload) => {
				const p = payload as { allow?: boolean; reason?: string } | undefined;
				const allow = p?.allow === true;
				const reason = allow ? "" : (p?.reason ?? `Blocked remotely (${labels})`);
				done(allow ? { allow: true } : { allow: false, reason });
			});
		}
		let optionIndex = 0;
		let inputMode = false;
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
			if (inputMode) {
				if (matchesKey(data, Key.escape)) {
					inputMode = false;
					editor.setText("");
					refresh();
					return;
				}
				editor.handleInput(data);
				refresh();
				return;
			}

			if (matchesKey(data, Key.up)) { optionIndex = 0; refresh(); return; }
			if (matchesKey(data, Key.down)) { optionIndex = 1; refresh(); return; }
			if (matchesKey(data, Key.enter)) {
				if (optionIndex === 0) {
					done({ allow: true });
				} else {
					inputMode = true;
					editor.setText("");
					refresh();
				}
				return;
			}
			if (matchesKey(data, Key.escape)) {
				done({ allow: false, reason: `Blocked by user (${labels})` });
			}
		}

		function render(width: number): string[] {
			if (cachedLines) return cachedLines;
			const lines: string[] = [];
			const add = (s: string) => lines.push(truncateToWidth(s, width));

			lines.push("");
			add(theme.fg("warning", " ⚠️ Dangerous command ") + theme.fg("muted", `(${labels})`));
			add(` ${theme.fg("text", command)}`);
			lines.push("");

			const opts = ["Yes", inputMode ? "No ✎" : "No"];
			for (let i = 0; i < opts.length; i++) {
				const sel = i === optionIndex;
				add(`${sel ? theme.fg("accent", " > ") : "   "}${theme.fg(sel ? "accent" : "text", opts[i])}`);
			}
			lines.push("");

			if (inputMode) {
				add(theme.fg("muted", " Reason:"));
				for (const line of editor.render(width - 2)) add(` ${line}`);
				lines.push("");
				add(theme.fg("dim", " Enter submit • Esc back"));
			} else {
				add(theme.fg("dim", " ↑↓ • Enter • Esc block"));
			}
			lines.push("");

			cachedLines = lines;
			return lines;
		}

		return { render, invalidate: () => { cachedLines = undefined; }, handleInput };
	});
}
