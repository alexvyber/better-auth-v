// Generated from pinned upstream source; do not edit assertions here.
import {describe,expect,it} from 'vitest';
import {getTestInstance} from '../harness/test-instance.js';

describe("runtime", async () => {
	it("should apply default value function on runtime", async () => {
		const { auth } = await getTestInstance({
			user: {
				additionalFields: {
					newField: {
						type: "string",
						defaultValue: () => "test",
						required: false,
					},
					dateField: {
						type: "date",
						defaultValue: () =>
							new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(),
						required: false,
					},
				},
			},
		});

		const res = await auth.api.signUpEmail({
			body: {
				email: "test2@test.com",
				name: "test",
				password: "test-password",
			},
		});
		const session = await auth.api.getSession({
			headers: {
				Authorization: `Bearer ${res.token}`,
			},
		});
		expect(session?.user.newField).toBe("test");
		expect(session?.user.dateField).toBeInstanceOf(Date);
		expect(session?.user.dateField?.getTime()).toBeGreaterThan(
			new Date(Date.now() + 1000 * 60 * 60 * 23).getTime(),
		);
	});
});
