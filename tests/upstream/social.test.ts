// Generated from pinned upstream source; do not edit assertions here.
import { describe, expect, it } from "vitest";
import { getTestInstance } from "../harness/test-instance.js";

describe("Google Provider - includeGrantedScopes", async () => {
	it("includes `include_granted_scopes=true` in the authorization URL by default", async () => {
		const { client } = await getTestInstance(
			{
				socialProviders: {
					google: {
						clientId: "test",
						clientSecret: "test",
					},
				},
			},
			{ disableTestUser: true },
		);

		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/callback",
		});

		const authUrl = new URL(signInRes.data!.url!);
		expect(authUrl.searchParams.get("include_granted_scopes")).toBe("true");
	});

	it("includes `include_granted_scopes=true` when explicitly enabled", async () => {
		const { client } = await getTestInstance(
			{
				socialProviders: {
					google: {
						clientId: "test",
						clientSecret: "test",
						includeGrantedScopes: true,
					},
				},
			},
			{ disableTestUser: true },
		);

		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/callback",
		});

		const authUrl = new URL(signInRes.data!.url!);
		expect(authUrl.searchParams.get("include_granted_scopes")).toBe("true");
	});

	it("lets additionalParams disable `include_granted_scopes` for a single flow", async () => {
		const { client } = await getTestInstance(
			{
				socialProviders: {
					google: {
						clientId: "test",
						clientSecret: "test",
					},
				},
			},
			{ disableTestUser: true },
		);

		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/callback",
			additionalParams: {
				include_granted_scopes: "false",
			},
		});

		const authUrl = new URL(signInRes.data!.url!);
		expect(authUrl.searchParams.get("include_granted_scopes")).toBe("false");
	});

	it("omits `include_granted_scopes` from the authorization URL when disabled", async () => {
		const { client } = await getTestInstance(
			{
				socialProviders: {
					google: {
						clientId: "test",
						clientSecret: "test",
						includeGrantedScopes: false,
					},
				},
			},
			{ disableTestUser: true },
		);

		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/callback",
			scopes: ["https://www.googleapis.com/auth/drive.file"],
		});

		const authUrl = new URL(signInRes.data!.url!);
		expect(authUrl.searchParams.has("include_granted_scopes")).toBe(false);
		expect(authUrl.searchParams.get("scope")).toContain("openid");
		expect(authUrl.searchParams.get("scope")).toContain(
			"https://www.googleapis.com/auth/drive.file",
		);
	});

	it("lets additionalParams re-enable `include_granted_scopes` for a single flow", async () => {
		const { client } = await getTestInstance(
			{
				socialProviders: {
					google: {
						clientId: "test",
						clientSecret: "test",
						includeGrantedScopes: false,
					},
				},
			},
			{ disableTestUser: true },
		);

		const signInRes = await client.signIn.social({
			provider: "google",
			callbackURL: "/callback",
			additionalParams: {
				include_granted_scopes: "true",
			},
		});

		const authUrl = new URL(signInRes.data!.url!);
		expect(authUrl.searchParams.get("include_granted_scopes")).toBe("true");
	});
});
