/**
 * permission-gate — bash tokenizer, brace expansion and heredoc machinery.
 *
 * Splits a command string into words, operators and substitution scripts.
 * Not a full shell parser: expansions are kept literal (${VAR} normalized
 * to $VAR so rules can match "$HOME"); arithmetic $((…)) stays an opaque
 * word but $() substitutions inside it are surfaced (bash runs them).
 * Quoting in all its spellings ('…', "…", $'…', $"…", \x) is decoded so
 * rules always see the argv bash would produce.
 *
 * shell.ts assembles these tokens into pipelines; argv.ts holds the
 * wrapper/executor knowledge applied to the resulting argvs.
 */

export type Token =
	| { type: "word"; value: string }
	| { type: "op"; value: string }
	// inner script of $(...), `...`, <(...) or >(...); `out` marks >(...) —
	// its process *consumes* the surrounding pipeline's output
	| { type: "sub"; value: string; out?: boolean }
	// body of << / <<- (stdin data): `cmd` is the sequence number of the
	// simple command that carried the << operator, so pipelines() can bind
	// the body to the right command even when an operator sits between <<
	// and the newline; `subs` are the $(…)/`…` scripts bash expands inside
	// the body when the delimiter was unquoted, empty for quoted delimiters.
	| { type: "heredoc"; value: string; cmd: number; subs: string[] };

// Multi-char operators first so e.g. "&&" is not split into "&" "&".
const OPERATORS = [
	"<<<",
	"<<-",
	"<<",
	">>",
	">|",
	"&&",
	"||",
	";;",
	"|&",
	"&>",
	">&",
	"<&",
	"|",
	"&",
	";",
	"(",
	")",
	"<",
	">",
	"\n",
];

// Redirects do not end a simple command; the word after them is a target
// (or herestring data), not an argument.
export const REDIRECT_OPS = new Set([">", ">>", ">|", "<", ">&", "<&", "&>", "<<<"]);

// Placeholder words the tokenizer leaves in argv where a command/process
// substitution appeared. Only referenced through these constants and
// hasSubPlaceholder, so the emitted and matched spellings cannot drift —
// a drift would silently stop the `bash <(curl …)` correlation from firing.
const DOLLAR_SUB_PLACEHOLDER = "$(...)";
const PROC_SUB_IN_PLACEHOLDER = "<(...)";
const PROC_SUB_OUT_PLACEHOLDER = ">(...)";

/** True if `word` contains a substitution placeholder emitted by the
 * tokenizer — i.e. this argv word consumes a `$(…)`/`<(…)` script's output. */
export function hasSubPlaceholder(word: string): boolean {
	return word.includes(DOLLAR_SUB_PLACEHOLDER) || word.includes(PROC_SUB_IN_PLACEHOLDER);
}

/** True if `word` is *exactly* one input substitution placeholder — the
 * whole word was a `$(…)`/`<(…)`, so everything it does lives in the
 * separately collected substitution script. The non-literal-command rule
 * exempts a lone such word: re-parsing eval/sh -c scripts turns their
 * placeholder words back into bare-placeholder argvs, and matching those
 * would false-positive on `eval "$(git rev-parse HEAD)"`. */
export function isSubPlaceholder(word: string): boolean {
	return word === DOLLAR_SUB_PLACEHOLDER || word === PROC_SUB_IN_PLACEHOLDER;
}

// Returns index after a quote-delimited region starting at `start`
// (the opening quote), honoring backslash escapes.
const skipQuoted = (input: string, start: number, quote: string): number => {
	let j = start + 1;
	while (j < input.length && input[j] !== quote) {
		j += input[j] === "\\" ? 2 : 1;
	}
	return Math.min(j + 1, input.length);
};

// Reads a heredoc delimiter starting at `start` (first char after << or
// <<-), returning the unquoted delimiter and the index after it. All
// spellings collapse to the bare word: quoting only decides whether bash
// expands the *body*, and readParenGroup copies bodies verbatim.
const readHeredocDelim = (input: string, start: number): [string, number] => {
	let j = start;
	while (input[j] === " " || input[j] === "\t") j++;
	let delim = "";
	while (j < input.length && !" \t\n;|&<>()".includes(input[j])) {
		const c = input[j];
		if (c === "\\") {
			delim += input[j + 1] ?? "";
			j += 2;
		} else if (c === "'" || c === '"') {
			const end = c === "'" ? input.indexOf("'", j + 1) : skipQuoted(input, j, c) - 1;
			const stop = end === -1 ? input.length : end;
			delim += input.slice(j + 1, stop);
			j = end === -1 ? input.length : stop + 1;
		} else {
			delim += c;
			j++;
		}
	}
	return [delim, j];
};

// Copies heredoc bodies verbatim from `start` (just after the newline that
// ended the command line) through each pending delimiter line, returning
// [text, nextIndex]. An unterminated body runs to the end, as in bash.
const readHeredocBodies = (
	input: string,
	start: number,
	pending: { delim: string; stripTabs: boolean }[],
): [string, number] => {
	let j = start;
	let text = "";
	for (const { delim, stripTabs } of pending) {
		while (j < input.length) {
			let lineEnd = input.indexOf("\n", j);
			if (lineEnd === -1) lineEnd = input.length;
			const line = input.slice(j, lineEnd);
			const stop = Math.min(lineEnd + 1, input.length);
			text += input.slice(j, stop);
			j = stop;
			if ((stripTabs ? line.replace(/^\t+/, "") : line) === delim) break;
		}
	}
	return [text, j];
};

// Reads a parenthesized group starting at index of "(" — the body of
// $(...), <(...) or >(...) — returning [inner, nextIndex]. Skips quoted
// regions, backticks, comments and heredoc bodies so a `)` inside them
// does not affect paren depth counting. Module-level (not a tokenize
// closure) so heredocSubstitutions can reuse it on heredoc bodies.
const readParenGroup = (input: string, start: number): [string, number] => {
	let depth = 1;
	let j = start + 1;
	let inner = "";
	let atWordStart = true;
	// Heredoc delimiters seen on the current line; their bodies are copied
	// verbatim once the line ends.
	const pendingHeredocs: { delim: string; stripTabs: boolean }[] = [];
	while (j < input.length && depth > 0) {
		const c = input[j];
		// A heredoc body is *data*, not shell text: an apostrophe, a leading
		// `#` or a `)` in a commit message (`git commit -m "$(cat <<'EOF' …
		// it's … EOF\n)"`) must not open a quote, start a comment or move
		// paren depth — any of those desyncs the reader and the substitution
		// swallows the rest of the command line. Operator, delimiter and body
		// are copied byte-for-byte so the re-parse of `inner` sees exactly
		// what bash sees.
		if (c === "<" && input[j + 1] === "<" && input[j + 2] !== "<") {
			const stripTabs = input[j + 2] === "-";
			const [delim, next] = readHeredocDelim(input, j + (stripTabs ? 3 : 2));
			inner += input.slice(j, next);
			pendingHeredocs.push({ delim, stripTabs });
			j = next;
			atWordStart = false;
			continue;
		}
		if (c === "\n" && pendingHeredocs.length) {
			const [body, next] = readHeredocBodies(input, j + 1, pendingHeredocs);
			inner += `\n${body}`;
			pendingHeredocs.length = 0;
			j = next;
			atWordStart = true;
			continue;
		}
		if (c === "'" || c === '"' || c === "`") {
			// no backslash escapes inside single quotes
			const end = c === "'" ? input.indexOf("'", j + 1) : -1;
			const stop = c === "'"
				? (end === -1 ? input.length : end + 1)
				: skipQuoted(input, j, c);
			inner += input.slice(j, stop);
			j = stop;
			atWordStart = false;
			continue;
		}
		if (c === "#" && atWordStart) {
			let end = input.indexOf("\n", j);
			if (end === -1) end = input.length;
			j = end;
			continue;
		}
		if (c === "\\") {
			inner += input.slice(j, j + 2);
			j += 2;
			atWordStart = false;
			continue;
		}
		atWordStart = " \t\n;|&(".includes(c);
		if (c === "(") depth++;
		else if (c === ")") {
			depth--;
			if (depth === 0) {
				j++;
				break;
			}
		}
		inner += c;
		j++;
	}
	return [inner, j];
};

// Reads a `...` starting at index after opening backtick.
const readBacktick = (input: string, start: number): [string, number] => {
	let j = start;
	let inner = "";
	while (j < input.length) {
		const c = input[j];
		if (c === "\\" && j + 1 < input.length) {
			// \` \\ \$ unescape inside backticks
			const next = input[j + 1];
			inner += "`\\$".includes(next) ? next : c + next;
			j += 2;
			continue;
		}
		if (c === "`") {
			j++;
			break;
		}
		inner += c;
		j++;
	}
	return [inner, j];
};

/**
 * Command substitutions bash runs inside an unquoted-delimiter heredoc
 * body — `$(…)` and backticks expand there no matter which program consumes
 * the body. Quote characters are *not* special in heredoc bodies (only
 * backslash before $, ` and \ escapes), so '$(…)' still expands — a plain
 * re-tokenize would wrongly skip it.
 */
export function heredocSubstitutions(body: string): string[] {
	const subs: string[] = [];
	let i = 0;
	while (i < body.length) {
		const c = body[i];
		if (c === "\\") {
			i += 2; // \$ and \` suppress expansion
			continue;
		}
		if (c === "$" && body[i + 1] === "(") {
			if (body[i + 2] === "(") {
				i += 3; // $((…)): arithmetic, but keep scanning for inner $()
				continue;
			}
			const [inner, next] = readParenGroup(body, i + 1);
			subs.push(inner);
			i = next;
			continue;
		}
		if (c === "`") {
			const [inner, next] = readBacktick(body, i + 1);
			subs.push(inner);
			i = next;
			continue;
		}
		i++;
	}
	return subs;
}

/** Tokenize a shell command string into words, operators and substitutions. */
export function tokenize(input: string): Token[] {
	const tokens: Token[] = [];
	let i = 0;
	let word = "";
	let inWord = false;
	// True if any part of the current word was quoted ('…', "…", $'…', \x) —
	// heredoc delimiters need it: only an unquoted delimiter makes bash
	// expand $(…)/`…` inside the body.
	let wordQuoted = false;
	// Sequence number of the simple command being tokenized, incremented on
	// every operator that ends a command. pipelines() counts identically, so
	// a heredoc token stamped with `cmd` finds its command even when an
	// operator sits between << and the body.
	let seq = 0;
	// Delimiters seen after << / <<- whose bodies still need to be skipped
	// once the current line ends.
	const pendingHeredocs: { delim: string; stripTabs: boolean; cmd: number; quoted: boolean }[] = [];
	let expectHeredoc: { stripTabs: boolean } | null = null;

	const pushWord = () => {
		if (!inWord) return;
		if (expectHeredoc) {
			pendingHeredocs.push({
				delim: word, stripTabs: expectHeredoc.stripTabs, cmd: seq, quoted: wordQuoted,
			});
			expectHeredoc = null;
		} else {
			tokens.push({ type: "word", value: word });
			// pipelines() treats bare { } words as command boundaries — count
			// them here too so seq stays in lockstep.
			if (word === "{" || word === "}") seq++;
		}
		word = "";
		inWord = false;
		wordQuoted = false;
	};

	// `start` must be right after a newline; returns index after the last
	// body. Bodies are emitted as heredoc tokens (not discarded): a heredoc
	// feeding a shell is a script (`bash <<EOF … EOF`), and only pipelines()
	// knows the receiving command — it decides shell vs. data.
	const collectHeredocBodies = (start: number): number => {
		let j = start;
		for (const { delim, stripTabs, cmd, quoted } of pendingHeredocs) {
			const lines: string[] = [];
			while (j < input.length) {
				let lineEnd = input.indexOf("\n", j);
				if (lineEnd === -1) lineEnd = input.length;
				let line = input.slice(j, lineEnd);
				if (stripTabs) line = line.replace(/^\t+/, "");
				j = lineEnd + 1;
				if (line === delim) break;
				lines.push(line);
			}
			const body = lines.join("\n");
			tokens.push({
				type: "heredoc", value: body, cmd,
				subs: quoted ? [] : heredocSubstitutions(body),
			});
		}
		pendingHeredocs.length = 0;
		return Math.min(j, input.length);
	};

	// Reads ${NAME} at index of "$"; simple names are normalized to $NAME.
	const readBraceVar = (start: number): [string, number] => {
		const end = input.indexOf("}", start + 2);
		if (end === -1) return [input.slice(start), input.length];
		const name = input.slice(start + 2, end);
		const text = /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)
			? `$${name}`
			: input.slice(start, end + 1);
		return [text, end + 1];
	};

	const pushSub = (inner: string, placeholder: string, next: number) => {
		tokens.push({
			type: "sub",
			value: inner,
			...(placeholder === PROC_SUB_OUT_PLACEHOLDER ? { out: true } : {}),
		});
		word += placeholder;
		inWord = true;
		i = next;
	};

	while (i < input.length) {
		const c = input[i];

		// Comment: only when not inside a word.
		if (c === "#" && !inWord) {
			while (i < input.length && input[i] !== "\n") i++;
			continue;
		}

		// Whitespace (newline is an operator, handled below).
		if (c === " " || c === "\t" || c === "\r") {
			pushWord();
			i++;
			continue;
		}

		// Backslash outside quotes (\<newline> is a line continuation).
		if (c === "\\") {
			if (i + 1 < input.length && input[i + 1] !== "\n") {
				word += input[i + 1];
				inWord = true;
				wordQuoted = true; // <<\EOF quotes the delimiter
			}
			i += 2;
			continue;
		}

		// ANSI-C quoting $'…': decode escapes, treat as literal content.
		if (c === "$" && input[i + 1] === "'") {
			let j = i + 2;
			while (j < input.length && input[j] !== "'") {
				j += input[j] === "\\" ? 2 : 1;
			}
			word += decodeAnsiC(input.slice(i + 2, Math.min(j, input.length)));
			inWord = true;
			wordQuoted = true;
			i = Math.min(j + 1, input.length);
			continue;
		}

		// Locale quoting $"…": the $ is irrelevant for matching — drop it and
		// let the double-quote branch handle the rest.
		if (c === "$" && input[i + 1] === '"') {
			i++;
			continue;
		}

		// Single quotes: literal.
		if (c === "'") {
			const end = input.indexOf("'", i + 1);
			const stop = end === -1 ? input.length : end;
			word += input.slice(i + 1, stop);
			inWord = true;
			wordQuoted = true;
			i = end === -1 ? input.length : end + 1;
			continue;
		}

		// Double quotes.
		if (c === '"') {
			inWord = true;
			wordQuoted = true;
			i++;
			while (i < input.length && input[i] !== '"') {
				const d = input[i];
				if (d === "\\" && i + 1 < input.length) {
					const next = input[i + 1];
					if ('"\\$`'.includes(next)) word += next;
					else if (next !== "\n") word += d + next; // \<newline> continues line
					i += 2;
				} else if (d === "$" && input[i + 1] === "(") {
					const [inner, next] = readParenGroup(input, i + 1);
					pushSub(inner, DOLLAR_SUB_PLACEHOLDER, next);
				} else if (d === "$" && input[i + 1] === "{") {
					const [text, next] = readBraceVar(i);
					word += text;
					i = next;
				} else if (d === "`") {
					const [inner, next] = readBacktick(input, i + 1);
					pushSub(inner, DOLLAR_SUB_PLACEHOLDER, next);
				} else {
					word += d;
					i++;
				}
			}
			i++; // closing quote
			continue;
		}

		// Command substitution and arithmetic outside quotes.
		if (c === "$" && input[i + 1] === "(") {
			if (input[i + 2] === "(") {
				// $(( ... )): the arithmetic stays an opaque word, but bash *does*
				// run $() command substitutions inside it — surface them as subs
				// so `: $(( $(rm -rf x) ))` still exposes the inner command.
				const end = input.indexOf("))", i + 3);
				const stop = end === -1 ? input.length : end + 2;
				let j = i + 3;
				while (j < stop - 1) {
					if (input[j] === "$" && input[j + 1] === "(" && input[j + 2] !== "(") {
						const [inner, next] = readParenGroup(input, j + 1);
						tokens.push({ type: "sub", value: inner });
						j = next;
					} else j++;
				}
				word += input.slice(i, stop);
				inWord = true;
				i = stop;
			} else {
				const [inner, next] = readParenGroup(input, i + 1);
				pushSub(inner, DOLLAR_SUB_PLACEHOLDER, next);
			}
			continue;
		}
		if (c === "`") {
			const [inner, next] = readBacktick(input, i + 1);
			pushSub(inner, DOLLAR_SUB_PLACEHOLDER, next);
			continue;
		}

		// ${VAR} outside quotes: normalize to $VAR.
		if (c === "$" && input[i + 1] === "{") {
			const [text, next] = readBraceVar(i);
			word += text;
			inWord = true;
			i = next;
			continue;
		}

		// Process substitution <(...) / >(...): scan contents too.
		if ((c === "<" || c === ">") && input[i + 1] === "(") {
			const [inner, next] = readParenGroup(input, i + 1);
			pushSub(inner, c === "<" ? PROC_SUB_IN_PLACEHOLDER : PROC_SUB_OUT_PLACEHOLDER, next);
			continue;
		}

		// Operators.
		const op = OPERATORS.find((o) => input.startsWith(o, i));
		if (op) {
			// A pure-digit word directly before a redirect is a file descriptor
			// (e.g. 2>&1), not an argument.
			if (inWord && /^\d+$/.test(word) && /^[<>]/.test(op)) {
				word = "";
				inWord = false;
				wordQuoted = false;
			}
			pushWord();
			if (op === "\n") {
				i++;
				// Bodies must be tokenized *before* the ";" so pipelines() can
				// attach a body to the still-open command carrying the <<.
				if (pendingHeredocs.length) i = collectHeredocBodies(i);
				tokens.push({ type: "op", value: ";" });
				seq++;
				continue;
			}
			tokens.push({ type: "op", value: op });
			if (op === "<<" || op === "<<-") {
				expectHeredoc = { stripTabs: op === "<<-" };
			} else if (!REDIRECT_OPS.has(op)) {
				seq++; // command-ending operator — pipelines() flushes here
			}
			i += op.length;
			continue;
		}

		// Regular character ($VAR stays literal).
		word += c;
		inWord = true;
		i++;
	}
	pushWord();
	return tokens;
}

// Decode ANSI-C $'…' escapes so `bash -c $'rm -rf /'` (or \x72m tricks)
// yields the same argv as the plain-quoted form.
function decodeAnsiC(s: string): string {
	return s.replace(
		/\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|[0-7]{1,3}|.)/g,
		(_, esc: string) => {
			if (esc[0] === "x") return String.fromCharCode(parseInt(esc.slice(1), 16));
			if (esc[0] === "u") return String.fromCharCode(parseInt(esc.slice(1), 16));
			if (/^[0-7]/.test(esc)) return String.fromCharCode(parseInt(esc, 8));
			const simple: Record<string, string> = {
				n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b",
				e: "\x1b", f: "\f", v: "\v", "0": "\0",
			};
			return simple[esc] ?? esc;
		},
	);
}

/** Collapse single-char bracket groups: bash expands `[c]` to `c` whenever
 * the resulting path exists, so `/bin/r[m]` runs rm and `/nix/stor[e]` is
 * /nix/store. Negated groups (`[!c]`, `[^c]`) match anything *but* the
 * char and stay literal. */
export const collapseBrackets = (w: string): string => w.replace(/\[([^\]^!])\]/g, "$1");

/**
 * Sentinel argv emitted when a parse budget (nesting depth, pipeline
 * stage count, wrapper unwrap steps) is exhausted. Budgets must fail
 * *closed* like their braceExpand / globCouldMatchRoot siblings:
 * returning nothing on exhaustion let 66×`eval` (or a 66-deep `$()`)
 * hide any payload from every rule — blocks included — behind a
 * mechanically simple prefix. The built-in "unparseable command (depth
 * budget)" rule matches this sentinel, so exhaustion prompts (and
 * hard-blocks headless) instead of silently allowing. A spoofed sentinel
 * ($'\0…' at command position) merely triggers the same prompt — the
 * safe direction. Defined here (not shell.ts) so argv.ts can emit it
 * without an import cycle; shell.ts re-exports it.
 */
export const PARSE_BUDGET_SENTINEL = "\u0000permission-gate:parse-budget";

// Brace expansion is a well-known gate-evasion idiom — `{sudo,id}` is one
// opaque word to the tokenizer but bash runs `sudo id`. Expand simple comma
// lists only: a comma is required (find's `{}` and awk's `{print $1}` stay
// literal), `${…}` parameter expansion is skipped, and budget exhaustion
// collapses to bash's own first expansion so adversarial input can neither
// blow up the parser nor hide behind the budget.
export function braceExpand(word: string): string[] {
	// Iterative, one group per pass, with a hard budget. The obvious
	// recursive flatMap is a DoS: the result cap only applies after the
	// recursion returns, so N groups cost 2^N calls before any cap fires
	// (`{a,b}` × 60 hangs the gate inside tool_call). Here every pass
	// expands one group across ≤32 live words, so work is O(groups × 32).
	let results = [word];
	for (;;) {
		const next: string[] = [];
		let changed = false;
		let exceeded = false;
		for (const w of results) {
			const m = /^(.*?)\{([^{}]*,[^{}]*)\}(.*)$/.exec(w);
			if (!m || m[1].endsWith("$")) {
				next.push(w);
				continue;
			}
			changed = true;
			for (const alt of m[2].split(",")) next.push(m[1] + alt + m[3]);
			if (next.length > 32) {
				exceeded = true;
				break;
			}
		}
		if (exceeded) {
			// Budget exhaustion must fail *closed*: bailing to the literal word
			// made 33+-way expansions invisible — `{r,r}{m,m}{,}{,}{,}{,} -rf /`
			// runs rm but matched nothing. Keep bash's own first word (first
			// alternative of every group) and keep expanding it.
			results = [next[0]];
			continue;
		}
		if (!changed) return next;
		results = next;
	}
}
