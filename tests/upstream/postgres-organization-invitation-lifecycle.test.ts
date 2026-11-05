// Generated from pinned upstream source; do not edit assertions here.
import {describe,expect,it,vi} from 'vitest';
import type {APIError} from 'better-auth/api';
import {createAccessControl} from 'better-auth/plugins/access';
import {adminAc,defaultStatements,memberAc,ownerAc} from 'better-auth/plugins/organization/access';
import {createAuthClient} from 'better-auth/client';
import {organizationClient,ORGANIZATION_ERROR_CODES} from 'better-auth/client/plugins';
import {organization} from '../harness/plugins.js';
import {getTestInstance} from '../harness/organization-postgres-text-fixture.js';

describe("invitation expiration and filtering", async () => {
	const { auth, signInWithUser } = await getTestInstance({
		plugins: [
			organization({
				invitationExpiresIn: 1, // 1 second expiration for testing
				async sendInvitationEmail() {},
			}),
		],
		databaseHooks: {
			user: {
				create: {
					before: async (user) => ({
						data: { ...user, emailVerified: true },
					}),
				},
			},
		},
	});

	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl: async (url, init) => {
				return auth.handler(new Request(url, init));
			},
		},
	});

	it("should allow rejecting expired invitations", async () => {
		const rng = crypto.randomUUID();
		const adminUser = {
			email: `admin-${rng}@email.com`,
			password: rng,
			name: `admin-${rng}`,
		};
		const invitedUser = {
			email: `invited-${rng}@email.com`,
			password: rng,
			name: `invited-${rng}`,
		};

		await auth.api.signUpEmail({ body: adminUser });
		await auth.api.signUpEmail({ body: invitedUser });

		const { headers: adminHeaders } = await signInWithUser(
			adminUser.email,
			adminUser.password,
		);
		const { headers: invitedHeaders } = await signInWithUser(
			invitedUser.email,
			invitedUser.password,
		);

		// Create organization and send invitation
		const org = await auth.api.createOrganization({
			body: { name: rng, slug: rng },
			headers: adminHeaders,
		});

		const invitation = await client.organization.inviteMember({
			organizationId: org?.id,
			email: invitedUser.email,
			role: "member",
			fetchOptions: { headers: adminHeaders },
		});

		expect(invitation.data).toBeDefined();

		// Wait for invitation to expire
		await new Promise((resolve) => setTimeout(resolve, 1100));

		// Rejecting expired invitation should succeed
		const rejectResult = await client.organization.rejectInvitation({
			invitationId: invitation.data!.id!,
			fetchOptions: { headers: invitedHeaders },
		});

		expect(rejectResult.error).toBeFalsy();
		expect(rejectResult.data?.invitation?.status).toBe("rejected");
	});

	it("should only list pending invitations for a user", async () => {
		const rng = crypto.randomUUID();
		const adminUser = {
			email: `admin2-${rng}@email.com`,
			password: rng,
			name: `admin2-${rng}`,
		};
		const invitedUser = {
			email: `invited2-${rng}@email.com`,
			password: rng,
			name: `invited2-${rng}`,
		};

		await auth.api.signUpEmail({ body: adminUser });
		await auth.api.signUpEmail({ body: invitedUser });

		const { headers: adminHeaders } = await signInWithUser(
			adminUser.email,
			adminUser.password,
		);
		const { headers: invitedHeaders } = await signInWithUser(
			invitedUser.email,
			invitedUser.password,
		);

		// Create two organizations
		const org1 = await auth.api.createOrganization({
			body: { name: `${rng}-org1`, slug: `${rng}-org1` },
			headers: adminHeaders,
		});
		const org2 = await auth.api.createOrganization({
			body: { name: `${rng}-org2`, slug: `${rng}-org2` },
			headers: adminHeaders,
		});

		// Create invitations
		const invitation1 = await client.organization.inviteMember({
			organizationId: org1?.id,
			email: invitedUser.email,
			role: "member",
			fetchOptions: { headers: adminHeaders },
		});
		const invitation2 = await client.organization.inviteMember({
			organizationId: org2?.id,
			email: invitedUser.email,
			role: "member",
			fetchOptions: { headers: adminHeaders },
		});

		expect(invitation1.data).toBeDefined();
		expect(invitation2.data).toBeDefined();

		// Accept one invitation
		await client.organization.acceptInvitation({
			invitationId: invitation1.data!.id!,
			fetchOptions: { headers: invitedHeaders },
		});

		// List user invitations - should only show pending ones (not accepted)
		const userInvitations = await client.organization.listUserInvitations({
			fetchOptions: { headers: invitedHeaders },
		});

		expect(userInvitations.data?.length).toBe(1);
		expect(userInvitations.data?.[0]?.id).toBe(invitation2.data?.id);
		expect(userInvitations.data?.[0]?.status).toBe("pending");
	});

	it("should not list rejected invitations", async () => {
		const rng = crypto.randomUUID();
		const adminUser = {
			email: `admin3-${rng}@email.com`,
			password: rng,
			name: `admin3-${rng}`,
		};
		const invitedUser = {
			email: `invited3-${rng}@email.com`,
			password: rng,
			name: `invited3-${rng}`,
		};

		await auth.api.signUpEmail({ body: adminUser });
		await auth.api.signUpEmail({ body: invitedUser });

		const { headers: adminHeaders } = await signInWithUser(
			adminUser.email,
			adminUser.password,
		);
		const { headers: invitedHeaders } = await signInWithUser(
			invitedUser.email,
			invitedUser.password,
		);

		// Create organization
		const org = await auth.api.createOrganization({
			body: { name: `${rng}-org`, slug: `${rng}-org` },
			headers: adminHeaders,
		});

		// Create invitation
		const invitation = await client.organization.inviteMember({
			organizationId: org?.id,
			email: invitedUser.email,
			role: "member",
			fetchOptions: { headers: adminHeaders },
		});

		expect(invitation.data).toBeDefined();

		// Reject the invitation
		await client.organization.rejectInvitation({
			invitationId: invitation.data!.id!,
			fetchOptions: { headers: invitedHeaders },
		});

		// List user invitations - should be empty since the only invitation was rejected
		const userInvitations = await client.organization.listUserInvitations({
			fetchOptions: { headers: invitedHeaders },
		});

		expect(userInvitations.data?.length).toBe(0);
	});
});

describe("dynamic access control should merge DB permissions with built-in roles", async () => {
	// Extend default ac with a custom resource that default roles don't cover
	const ac = createAccessControl({
		...defaultStatements,
		sales: ["create", "read", "update", "delete"],
	});
	const { auth, signInWithTestUser, db } = await getTestInstance({
		plugins: [
			organization({
				ac,
				roles: {
					owner: ownerAc,
					admin: adminAc,
					member: memberAc,
				},
				dynamicAccessControl: {
					enabled: true,
				},
			}),
		],
	});

	const { headers } = await signInWithTestUser();

	const org = await auth.api.createOrganization({
		body: {
			name: "test-dac",
			slug: "test-dac",
		},
		headers,
	});
	if (!org) throw new Error("Organization not created");

	it("should merge DB permissions with built-in role permissions", async () => {
		// Insert an "owner" role record in DB with only sales permissions.
		// The built-in ownerAc does NOT have sales at all.
		await db.create({
			model: "organizationRole",
			data: {
				organizationId: org.id,
				role: "owner",
				permission: JSON.stringify({
					sales: ["create", "read", "delete"],
				}),
				createdAt: new Date(),
			},
		});

		// DB adds sales:delete which the built-in owner doesn't have
		const salesDelete = await auth.api.hasPermission({
			headers,
			body: {
				permissions: {
					sales: ["delete"],
				},
			},
		});
		expect(salesDelete.success).toBe(true);

		// Built-in ownerAc has organization:["update","delete"], which is NOT in the DB record.
		// Merge should preserve it.
		const orgDelete = await auth.api.hasPermission({
			headers,
			body: {
				permissions: {
					organization: ["delete"],
				},
			},
		});
		expect(orgDelete.success).toBe(true);
	});

	it("should not lose built-in actions when DB defines partial actions for the same resource", async () => {
		// Clean up previous test data
		await db.delete({
			model: "organizationRole",
			where: [{ field: "organizationId", value: org.id }],
		});

		// Built-in ownerAc has organization:["update","delete"].
		// DB only defines organization:["update"] (missing "delete").
		// Merge should preserve both actions.
		await db.create({
			model: "organizationRole",
			data: {
				organizationId: org.id,
				role: "owner",
				permission: JSON.stringify({
					organization: ["update"],
				}),
				createdAt: new Date(),
			},
		});

		const orgUpdate = await auth.api.hasPermission({
			headers,
			body: {
				permissions: {
					organization: ["update"],
				},
			},
		});
		expect(orgUpdate.success).toBe(true);

		// "delete" is only in built-in, not in DB -> must still be preserved
		const orgDelete = await auth.api.hasPermission({
			headers,
			body: {
				permissions: {
					organization: ["delete"],
				},
			},
		});
		expect(orgDelete.success).toBe(true);
	});
});

describe("invitation limit", async () => {
	const { customFetchImpl, signInWithTestUser } = await getTestInstance({
		plugins: [
			organization({
				invitationLimit: 1,
				async sendInvitationEmail(data, request) {},
			}),
		],
	});
	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl,
		},
	});
	const { headers } = await signInWithTestUser();
	const org = await client.organization.create(
		{
			name: "test",
			slug: "test",
		},
		{
			headers,
		},
	);

	it("should invite member to organization", async () => {
		const invite = await client.organization.inviteMember({
			organizationId: org.data?.id as string,
			email: "test6@test.com",
			role: "member",
			fetchOptions: {
				headers,
			},
		});
		expect(invite.data?.status).toBe("pending");
	});

	it("should throw error when invitation limit is reached", async () => {
		const invite = await client.organization.inviteMember({
			organizationId: org.data?.id as string,
			email: "test7@test.com",
			role: "member",
			fetchOptions: {
				headers,
			},
		});
		expect(invite.error?.status).toBe(403);
		expect(invite.error?.message).toBe(
			ORGANIZATION_ERROR_CODES.INVITATION_LIMIT_REACHED.message,
		);
	});

	it("should throw error with custom invitation limit", async () => {
		const { auth, signInWithTestUser } = await getTestInstance({
			plugins: [
				organization({
					invitationLimit: async (data, ctx) => {
						return 0;
					},
				}),
			],
		});
		const { headers } = await signInWithTestUser();
		const org = await auth.api.createOrganization({
			body: {
				name: "test",
				slug: "test",
			},
			headers,
		});
		await auth.api
			.createInvitation({
				body: {
					email: "test8@test.com",
					role: "member",
					organizationId: org?.id as string,
				},
				headers,
			})
			.catch((e: APIError) => {
				expect(e.message).toBe(
					ORGANIZATION_ERROR_CODES.INVITATION_LIMIT_REACHED.message,
				);
			});
	});
});

describe("cancel pending invitations on re-invite", async () => {
	const { customFetchImpl, signInWithTestUser } = await getTestInstance({
		plugins: [
			organization({
				cancelPendingInvitationsOnReInvite: true,
			}),
		],
	});
	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl,
		},
	});
	const { headers } = await signInWithTestUser();
	const org = await client.organization.create(
		{
			name: "test",
			slug: "test",
		},
		{
			headers,
		},
	);

	it("should cancel pending invitations on re-invite", async () => {
		const invite = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test9@test.com",
				role: "member",
			},
			{
				headers,
			},
		);
		expect(invite.data?.status).toBe("pending");
		const invite2 = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test9@test.com",
				role: "member",
				resend: true,
			},
			{
				headers,
			},
		);
		expect(invite2.data?.status).toBe("pending");
		const listInvitations = await client.organization.listInvitations({
			fetchOptions: {
				headers,
			},
		});
		expect(
			listInvitations.data?.filter((invite) => invite.status === "pending")
				.length,
		).toBe(1);
	});

	/**
	 * @see https://github.com/better-auth/better-auth/issues/9452
	 */
	it("should cancel pending invitation and create a new one when re-inviting without resend", async () => {
		const invite = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test9b@test.com",
				role: "member",
			},
			{
				headers,
			},
		);
		expect(invite.data?.status).toBe("pending");
		const originalInviteId = invite.data?.id;

		const invite2 = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test9b@test.com",
				role: "member",
			},
			{
				headers,
			},
		);
		expect(invite2.error).toBeNull();
		expect(invite2.data?.status).toBe("pending");
		expect(invite2.data?.id).not.toBe(originalInviteId);

		const listInvitations = await client.organization.listInvitations({
			fetchOptions: {
				headers,
			},
		});
		expect(
			listInvitations.data?.filter(
				(i) => i.email === "test9b@test.com" && i.status === "pending",
			).length,
		).toBe(1);
		expect(
			listInvitations.data?.filter(
				(i) => i.email === "test9b@test.com" && i.status === "canceled",
			).length,
		).toBe(1);
	});
});

describe("re-invite without cancelPendingInvitationsOnReInvite still throws", async () => {
	const { customFetchImpl, signInWithTestUser } = await getTestInstance({
		plugins: [organization()],
	});
	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl,
		},
	});
	const { headers } = await signInWithTestUser();
	const org = await client.organization.create(
		{
			name: "test",
			slug: "test",
		},
		{
			headers,
		},
	);

	/**
	 * @see https://github.com/better-auth/better-auth/issues/9452
	 */
	it("should still throw USER_IS_ALREADY_INVITED when option is disabled", async () => {
		const invite = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test9c@test.com",
				role: "member",
			},
			{
				headers,
			},
		);
		expect(invite.data?.status).toBe("pending");

		const invite2 = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test9c@test.com",
				role: "member",
			},
			{
				headers,
			},
		);
		expect(invite2.error?.message).toBe(
			ORGANIZATION_ERROR_CODES.USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION
				.message,
		);
	});
});

describe("resend invitation should reuse existing", async () => {
	const { customFetchImpl, signInWithTestUser } = await getTestInstance({
		plugins: [
			organization({
				async sendInvitationEmail(data, request) {},
			}),
		],
	});
	const client = createAuthClient({
		plugins: [organizationClient()],
		baseURL: "http://localhost:3000/api/auth",
		fetchOptions: {
			customFetchImpl,
		},
	});
	const { headers } = await signInWithTestUser();
	const org = await client.organization.create(
		{
			name: "test",
			slug: "test",
		},
		{
			headers,
		},
	);

	it("should reuse existing invitation when resend is true", async () => {
		const invite = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test10@test.com",
				role: "member",
			},
			{
				headers,
			},
		);
		expect(invite.data?.status).toBe("pending");
		const originalInviteId = invite.data?.id;

		const invite2 = await client.organization.inviteMember(
			{
				organizationId: org.data?.id as string,
				email: "test10@test.com",
				role: "member",
				resend: true,
			},
			{
				headers,
			},
		);
		expect(invite2.data?.status).toBe("pending");
		// Should return the same invitation ID, not create a new one
		expect(invite2.data?.id).toBe(originalInviteId);

		const listInvitations = await client.organization.listInvitations({
			fetchOptions: {
				headers,
			},
		});
		// Should still only have 1 pending invitation, not 2
		expect(
			listInvitations.data?.filter((invite) => invite.status === "pending")
				.length,
		).toBe(1);
	});
});
