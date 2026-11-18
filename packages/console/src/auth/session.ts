import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";
import type { OidcConfig, RuntimeConfig } from "../config";
import type { TokenSource } from "../api/client";

export interface Session {
  readonly subject: string;
  /** The OIDC email claim, when the provider chooses to issue one. */
  readonly email?: string;
  readonly displayName?: string;
}

export interface CompletedSession extends Session {
  /** Same-origin path the operator was heading to before sign-in began. */
  readonly returnTo?: string;
}

export interface AuthDriver extends TokenSource {
  initialize(): Promise<Session | undefined>;
  /** `returnTo` survives the identity-provider round trip, query string included. */
  signIn(returnTo?: string): Promise<void>;
  completeSignIn(): Promise<CompletedSession | undefined>;
  signOut(): Promise<void>;
  /** Returns a token valid for at least `minValidityMs`, renewing it first when needed. */
  accessToken(minValidityMs?: number): Promise<string | undefined>;
}

/** Only a plain absolute path on this origin may be restored after sign-in. */
export const safeReturnTo = (value: unknown): string | undefined =>
  typeof value === "string" && /^\/(?![/\\])/.test(value) && !value.startsWith("/auth/callback")
    ? value
    : undefined;

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

  public async signIn(returnTo?: string): Promise<void> {
    const target = safeReturnTo(returnTo);
    await this.manager.signinRedirect(target === undefined ? {} : { state: { returnTo: target } });
  }

  public async completeSignIn(): Promise<CompletedSession | undefined> {
    const user = await this.manager.signinRedirectCallback();
    const { token: _token, ...session } = this.adopt(user);
    const returnTo = safeReturnTo((user.state as { returnTo?: unknown } | undefined)?.returnTo);
    return returnTo === undefined ? session : { ...session, returnTo };
  }


  public async signOut(): Promise<void> {
    this.token = undefined;
    this.expiresAt = 0;
    await this.manager.signoutRedirect();
  }

  public async accessToken(minValidityMs = 30_000): Promise<string | undefined> {
    if (this.token !== undefined && Date.now() < this.expiresAt - minValidityMs) {
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
    const email = typeof claims.email === "string" ? claims.email : undefined;
    return {
      subject: user.profile.sub,
      ...(email === undefined ? {} : { email }),
      displayName:
        email ??
        (typeof user.profile.preferred_username === "string"
          ? user.profile.preferred_username
          : typeof claims.name === "string"
            ? claims.name
            : undefined),
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
  public async completeSignIn(): Promise<CompletedSession> {
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
