// Generated from pinned upstream source; do not edit assertions here.
import {describe,expect,expectTypeOf,it} from 'vitest';
import type {Session} from 'better-auth';
import {createAuthClient} from 'better-auth/client';
import {createAuthClient as createReactAuthClient} from 'better-auth/react';
import {inferAdditionalFields,twoFactorClient} from 'better-auth/client/plugins';
import {twoFactor} from '../harness/plugins.js';
import {betterAuth} from '../harness/constructor.js';
import {getTestInstance} from '../harness/test-instance.js';

describe("additionalFields", async () => {
	const { auth, signInWithTestUser, customFetchImpl, sessionSetter } =
		await getTestInstance({
			plugins: [twoFactor()],
			user: {
				additionalFields: {
					newField: {
						type: "string",
						defaultValue: "default-value",
					},
					nonRequiredFiled: {
						type: "string",
						required: false,
					},
				},
			},
		});;;;;

	it("should infer it on the client", async () => {
		const client = createAuthClient({
			plugins: [inferAdditionalFields<typeof auth>()],
		});
		type t = Awaited<ReturnType<typeof client.getSession>>["data"];
		expectTypeOf<t>().toMatchTypeOf<{
			user: {
				id: string;
				email: string;
				emailVerified: boolean;
				name: string;
				createdAt: Date;
				updatedAt: Date;
				image?: string | undefined;
				newField: string;
				nonRequiredFiled?: string | undefined;
			};
			session: Session;
		} | null>;
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/9770
	 */
	it("should infer session additional fields on updateSession", () => {
		const auth = betterAuth({
			session: {
				additionalFields: {
					color: {
						type: "string",
						required: false,
					},
					internalNote: {
						type: "string",
						input: false,
						required: false,
					},
				},
			},
		});
		const client = createAuthClient({
			plugins: [inferAdditionalFields<typeof auth>()],
		});

		type UpdateSessionBody = NonNullable<
			Parameters<typeof client.updateSession>[0]
		>;

		const body = {
			color: "blue",
		} satisfies UpdateSessionBody;
		expect(body.color).toBe("blue");
		expectTypeOf<UpdateSessionBody>().toMatchTypeOf<{
			color?: string | null | undefined;
		}>();

		const blockedBody = {
			// @ts-expect-error input: false fields must not be client-updateable.
			internalNote: "hidden",
		} satisfies UpdateSessionBody;
		void blockedBody;
	});

	it("should infer it on the client without direct import", async () => {
		const client = createAuthClient({
			plugins: [
				inferAdditionalFields({
					user: {
						newField: {
							type: "string",
						},
					},
				}),
			],
		});
		type t = Awaited<ReturnType<typeof client.getSession>>["data"];
		expectTypeOf<t>().toMatchTypeOf<{
			user: {
				id: string;
				email: string;
				emailVerified: boolean;
				name: string;
				createdAt: Date;
				updatedAt: Date;
				image?: string | undefined;
				newField: string;
			};
			session: Session;
		} | null>;
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/7982
	 */
	it("should infer additional fields on signIn response with manual schema", async () => {
		const client = createReactAuthClient({
			plugins: [
				inferAdditionalFields({
					user: {
						role: {
							type: "string",
						},
						phone: {
							type: "string",
							required: false,
						},
					},
				}),
			],
		});

		const signInEmail = () =>
			client.signIn.email({
				email: "test@example.com",
				password: "test-password",
			});
		type SignInData = Awaited<ReturnType<typeof signInEmail>>["data"];
		type SignInUser = NonNullable<SignInData>["user"];
		expectTypeOf<SignInUser["phone"]>().toEqualTypeOf<
			string | undefined | null
		>();
		expectTypeOf<SignInUser["role"]>().toEqualTypeOf<string>();
	});;;
});
