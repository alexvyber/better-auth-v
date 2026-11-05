import { expect } from "vitest";
import { createTestSuite } from "../../harness/adapter-suite.js";
import { getNormalTestSuiteTests } from "./basic.js";

export const joinsTestSuite = createTestSuite(
	"joins",
	{
		defaultBetterAuthOptions: {
			advanced: {
				database: {
					joins: true,
				},
			},
		},
		alwaysMigrate: true,
		prefixTests: "joins",
	},
	(helpers) => {
		const { "create - should use generateId if provided": _, ...normalTests } =
			getNormalTestSuiteTests({ ...helpers });

		return {
			"init - tests": async () => {
				const opts = helpers.getBetterAuthOptions();
				expect(opts.advanced?.database?.joins).toBe(true);
			},
			...normalTests,
		};
	},
);
