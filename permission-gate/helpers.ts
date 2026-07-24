/**
 * permission-gate — argv predicate combinators.
 *
 * Shared by the built-in rules (builtin-rules.ts) and user rules.ts
 * factories (exposed via GateHelpers, see types.ts): user rules face the
 * same wrapper-hiding pitfalls the built-ins were hardened against, so
 * they get the same primitives instead of reimplementing them.
 */

import type { ArgvPipeline } from "./types.ts";
import { unwrapSteps } from "./shell.ts";

/** True if any short-option cluster in args contains `letter`, or any arg equals `long`. */
export function hasFlag(args: string[], letter: string, long?: string): boolean {
	return args.some((a) =>
		(long && a === long) ||
		(/^-[^-]/.test(a) && a.slice(1).includes(letter)),
	);
}

/** Match any argv in the pipeline whose program is `cmd` (or one of `cmd`). */
export function anyCmd(
	pipeline: ArgvPipeline,
	cmd: string | string[],
	pred?: (args: string[]) => boolean,
): boolean {
	const names = Array.isArray(cmd) ? cmd : [cmd];
	// Every unwrap step must be checked, not just the final argv: unwrapping
	// strips sudo/doas/pkexec themselves, so matching only the end result
	// would let `env sudo whoami` hide sudo behind any wrapper prefix.
	return pipeline.some((rawArgv) =>
		unwrapSteps(rawArgv).some(
			(argv) => names.includes(argv[0]) && (!pred || pred(argv.slice(1))),
		),
	);
}
