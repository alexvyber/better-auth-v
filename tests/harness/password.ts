import { afterAll } from "vitest";
import { Bridge } from "./bridge.js";

let instance: Bridge | undefined;
let ready: Promise<unknown> | undefined;
async function bridge() {
  if (!instance) {
    instance = new Bridge();
    ready = instance.send("init");
  }
  await ready;
  return instance;
}
afterAll(async () => {
  await instance?.close();
});

export async function hashPassword(password: string): Promise<string> {
  const reply = await (await bridge()).send("password-hash", { password });
  return JSON.parse(reply.value_json) as string;
}

export async function verifyPassword(input: {
  hash: string;
  password: string;
}): Promise<boolean> {
  const reply = await (await bridge()).send("password-verify", input);
  return JSON.parse(reply.value_json) as boolean;
}
