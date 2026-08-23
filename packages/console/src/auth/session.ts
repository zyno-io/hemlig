import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import type { OidcConfig, RuntimeConfig } from "../config";
import type { TokenSource } from "../api/client";

export interface Session {
  readonly subject: string;
  readonly displayName?: string;
}

export interface AuthDriver extends TokenSource {
  initialize(): Promise<Session | undefined>;
  signIn(): Promise<void>;
  completeSignIn(): Promise<Session | undefined>;
  signOut(): Promise<void>;
}

/**
 * The access token lives only in this closure. It is never written to
 * localStorage, sessionStorage, or a cookie, and no refresh token is
 * persisted: a reload attempts a silent renew and otherwise redirects.
 */
class OidcDriver implements AuthDriver {
  private readonly manager: UserManager;
  private token: string | undefined;
  private expiresAt = 0;

  public constructor(config: OidcConfig) {
    this.manager = new UserManager({
      authority: config.authority,
      client_id: config.clientId,
      redirect_uri: `${window.location.origin}/auth/callback`,
      // A standalone document, not an SPA route: the provider redirects the
      // hidden renewal iframe back to it, so the console frames its own
      // origin here, which needs its own `frame-ancestors 'self'` response
      // header policy. Booting the whole app in that iframe just to call
      // one function would also be wasted work.
      silent_redirect_uri: `${window.location.origin}/silent.html`,
      post_logout_redirect_uri: window.location.origin,
      response_type: "code",
      scope: config.scopes.join(" "),
      automaticSilentRenew: true,
      // In-memory only. The default store is localStorage, which would leave
      // administrator tokens readable by any script that reaches this origin.
      userStore: new WebStorageStateStore({ store: new InMemoryStorage() }),
      stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
      loadUserInfo: false,
    });
    this.manager.events.addUserLoaded((user) => {
      this.adopt(user);
    });
    this.manager.events.addUserUnloaded(() => {
      this.token = undefined;
      this.expiresAt = 0;
    });
  }

  public async initialize(): Promise<Session | undefined> {
    try {
      const user = await this.manager.signinSilent();
      return user === null ? undefined : this.adopt(user);
    } catch {
      return undefined;
    }
  }

  public async signIn(): Promise<void> {
    await this.manager.signinRedirect();
  }

  public async completeSignIn(): Promise<Session | undefined> {
    const user = await this.manager.signinRedirectCallback();
    return this.adopt(user);
  }


  public async signOut(): Promise<void> {
    this.token = undefined;
    this.expiresAt = 0;
    await this.manager.signoutRedirect();
  }

  public async accessToken(): Promise<string | undefined> {
    if (this.token !== undefined && Date.now() < this.expiresAt - 30_000) {
      return this.token;
    }
    try {
      const user = await this.manager.signinSilent();
      return user === null ? undefined : this.adopt(user).token;
    } catch {
      return undefined;
    }
  }

  private adopt(user: User): Session & { token: string | undefined } {
    this.token = user.access_token;
    this.expiresAt = (user.expires_at ?? 0) * 1000;
    const claims = user.profile as Record<string, unknown>;
    return {
      subject: user.profile.sub,
      displayName:
        typeof claims.name === "string" ? claims.name : user.profile.preferred_username,
      token: this.token,
    };
  }
}

class InMemoryStorage implements Storage {
  private readonly entries = new Map<string, string>();
  public get length(): number {
    return this.entries.size;
  }
  public clear(): void {
    this.entries.clear();
  }
  public getItem(key: string): string | null {
    return this.entries.get(key) ?? null;
  }
  public key(index: number): string | null {
    return [...this.entries.keys()][index] ?? null;
  }
  public removeItem(key: string): void {
    this.entries.delete(key);
  }
  public setItem(key: string, value: string): void {
    this.entries.set(key, value);
  }
}

/**
 * MiniStack has no API Gateway and no identity provider, so local development
 * cannot obtain a real token. The dev bridge resolves the actor from a header
 * instead. `parseRuntimeConfig` refuses this mode for a non-loopback API.
 */
class DevBridgeDriver implements AuthDriver {
  public constructor(private readonly subject: string) {}
  public get devSubject(): string {
    return this.subject;
  }
  public async initialize(): Promise<Session> {
    return { subject: this.subject, displayName: `${this.subject} (dev bridge)` };
  }
  public async signIn(): Promise<void> {}
  public async completeSignIn(): Promise<Session> {
    return this.initialize();
  }
  public async signOut(): Promise<void> {}
  public async accessToken(): Promise<undefined> {
    return undefined;
  }
}

export const createAuthDriver = (config: RuntimeConfig): AuthDriver =>
  config.auth.mode === "oidc"
    ? new OidcDriver(config.auth)
    : new DevBridgeDriver(config.auth.subject);
