/**
 * permission-gate — shared table-test helper.
 *
 * Test names are the inputs themselves (JSON-quoted for command strings,
 * space-joined for argv arrays), so a failure is instantly greppable to
 * the exact command and `bun test -t 'rg --files'` style filtering works.
 */

import { expect, test } from "bun:test";

/** Run `fn` over each `[input, expected]` case as its own named test. */
export function table<I extends string | string[], O>(fn: (input: I) => O, cases: [I, O][]): void {
	for (const [input, expected] of cases) {
		const name = typeof input === "string" ? JSON.stringify(input) : input.join(" ");
		test(name, () => {
			expect(fn(input)).toEqual(expected);
		});
	}
}
