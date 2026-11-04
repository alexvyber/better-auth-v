import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { STATUS_CODES } from "node:http";
import { fileURLToPath } from "node:url";
import { AsyncLocalStorage, AsyncResource } from "node:async_hooks";
import { setTimeout, clearTimeout } from "node:timers";

export const recordMetadata = Symbol("V internal session metadata");
export function transportJSON(value: unknown): string {
  return JSON.stringify(value, (_key, item) => {
    if (item && typeof item === "object" && recordMetadata in item) return { ...item, $vSession: item[recordMetadata] };
    return item;
  });
}

export interface WireResponse {
  status: number;
  status_text: string;
  headers: { name: string; value: string }[];
  body: string;
}

export interface WireEmail {
  kind: string;
  user: Record<string, unknown>;
  token: string;
  url: string;
}

interface Reply {
  id: number;
  error: string | null;
  response: WireResponse | null;
  emails: WireEmail[];
  logs: { level: string; message: string }[];
  records_json: string;
  value_json: string;
}

export class Bridge {
  private child: ChildProcessWithoutNullStreams;
  private sequence = 0;
  private pending = new Map<
    number,
    {
      resolve: (reply: Reply) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private stderr = "";
  private closed = false;
  private queue: Promise<unknown> = Promise.resolve();
  private callbackContext = new AsyncLocalStorage<boolean>();
  private callbackScope: <T>(callback: () => T) => T = (callback) => callback();
  private callbacks = new Map<
    string,
    (payload: any) => unknown | Promise<unknown>
  >();

  setCallback(
    method: string,
    callback: (payload: any) => unknown | Promise<unknown>,
  ) {
    this.callbacks.set(method, callback);
  }

  removeCallback(method: string) { this.callbacks.delete(method); }

  constructor() {
    this.child = spawn(
      fileURLToPath(new URL("../../build/auth-bridge", import.meta.url)),
      [],
      {
        stdio: "pipe",
      },
    );
    this.child.stderr.on("data", (chunk) => {
      this.stderr = (this.stderr + chunk).slice(-8192);
    });
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      try {
        const frame = JSON.parse(line);
        if (typeof frame.callback === "string") {
          void this.replyToCallback(frame.callback, frame.payload, frame.callback_id, frame.context === true);
          return;
        }
        const reply = frame as Reply;
        const pending = this.pending.get(reply.id);
        if (!pending) throw new Error(`Unexpected bridge reply ${reply.id}`);
        clearTimeout(pending.timer);
        this.pending.delete(reply.id);
        if (reply.error) pending.reject(new Error(reply.error));
        else pending.resolve(reply);
      } catch (error) {
        this.abort(error instanceof Error ? error : new Error(String(error)));
      }
    });
    this.child.stdin.on("error", (error) => this.abort(error));
    this.child.on("error", (error) => this.abort(error));
    this.child.on("exit", (code, signal) => {
      this.closed = true;
      for (const pending of this.pending.values()) {
        clearTimeout(pending.timer);
        pending.reject(
          new Error(`V bridge exited (${code ?? signal}): ${this.stderr}`),
        );
      }
      this.pending.clear();
    });
  }

  private async replyToCallback(method: string, payload: unknown, callbackId: string, context: boolean) {
    try {
      const callback = this.callbacks.get(method);
      if (!callback) throw new Error(`Unsupported callback: ${method}`);
      const value = await this.callbackScope(() => this.callbackContext.run(context, () => callback(payload)));
      this.child.stdin.write(
        JSON.stringify({
          op: "callback-result",
          callback_id: callbackId,
          value_json: transportJSON(value ?? null),
        }) + "\n",
      );
    } catch (error) {
      this.child.stdin.write(
        JSON.stringify({
          op: "callback-result",
          callback_id: callbackId,
          error: error instanceof Error ? error.message : String(error),
        }) + "\n",
      );
    }
  }

  private abort(error: Error) {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
    this.child.kill();
    this.closed = true;
  }

  send(op: string, data: Record<string, unknown> = {}): Promise<Reply> {
    const callback = this.callbackContext.getStore();
    if (callback !== undefined) {
      if (!callback || !["internal", "inspect"].includes(op)) return Promise.reject(new Error("This callback cannot reenter public auth; database hooks can use their internal adapter"));
      return this.sendCommand(op, data);
    }
    const result = this.queue.then(() => this.sendCommand(op, data));
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private sendCommand(
    op: string,
    data: Record<string, unknown>,
  ): Promise<Reply> {
    if (this.closed) return Promise.reject(new Error("V bridge is closed"));
    const resource = new AsyncResource("better-auth-v-command");
    this.callbackScope = (callback) => resource.runInAsyncScope(callback);
    const id = ++this.sequence;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.abort(new Error(`V bridge timed out on ${op}: ${this.stderr}`));
      }, 15000);
      this.pending.set(id, { resolve, reject, timer });
      const commandTime = Date.now();
      this.child.stdin.write(
        JSON.stringify({
          id,
          op,
          now: Math.floor(commandTime / 1000),
          now_millis: commandTime,
          ...data,
        }) + "\n",
      );
    });
  }

  async close() {
    if (this.closed) return;
    try {
      await this.send("close");
      this.child.stdin.end();
    } finally {
      this.closed = true;
      this.child.kill();
    }
  }

  async request(request: Request, direct = false) {
    const reply = await this.send("request", {
      direct,
      request: {
        method: request.method,
        url: request.url,
        headers: Object.fromEntries(request.headers),
        body: await request.text(),
      },
    });
    if (!reply.response) throw new Error("Bridge returned no response");
    const headers = new Headers();
    for (const header of reply.response.headers)
      headers.append(header.name, header.value);
    return {
      response: new Response(
        reply.response.status === 204 ? null : reply.response.body,
        {
          status: reply.response.status,
          statusText: reply.response.status_text || STATUS_CODES[reply.response.status] || "",
          headers,
        },
      ),
      emails: reply.emails,
      logs: reply.logs,
    };
  }
}
