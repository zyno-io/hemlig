import { defineStore } from "pinia";
import { ref, shallowRef } from "vue";
import { HemligApi } from "../api/client";
import type { RuntimeConfig } from "../config";
import { createAuthDriver, type AuthDriver, type CompletedSession, type Session } from "../auth/session";

const SIGNED_OUT_KEY = "hemlig.signedOut";

// Survives the identity-provider round trip (and the local-only fallback's page
// load) so an explicit sign-out is not undone by an automatic sign-in. Storage
// can be unavailable; the in-memory ref still holds for the current page.
const readSignedOut = (): boolean => {
  try {
    return window.sessionStorage.getItem(SIGNED_OUT_KEY) === "1";
  } catch {
    return false;
  }
};
const writeSignedOut = (value: boolean): void => {
  try {
    if (value) {
      window.sessionStorage.setItem(SIGNED_OUT_KEY, "1");
    } else {
      window.sessionStorage.removeItem(SIGNED_OUT_KEY);
    }
  } catch {
    // Not persisted; see above.
  }
};

/**
 * Holds only session and environment context. Nothing derived from the API is
 * cached here; server state belongs to vue-query, and payload material belongs
 * to the editor component's local state and nowhere else.
 */
export const useAppStore = defineStore("app", () => {
  const config = shallowRef<RuntimeConfig | undefined>();
  const auth = shallowRef<AuthDriver | undefined>();
  const api = shallowRef<HemligApi | undefined>();
  const session = ref<Session | undefined>();
  const bootError = ref<string | undefined>();
  /** Set by an explicit sign-out; cleared only by the Sign in button or a completed sign-in. */
  const signedOut = ref(readSignedOut());

  const initialize = async (runtime: RuntimeConfig): Promise<void> => {
    config.value = runtime;
    const driver = createAuthDriver(runtime);
    auth.value = driver;
    api.value = new HemligApi(runtime, driver);
    // After an explicit sign-out, do not silently renew from the provider's
    // session (providers without an end-session endpoint still hold one).
    session.value = signedOut.value ? undefined : await driver.initialize();
  };

  const requireAuth = (): AuthDriver => {
    if (auth.value === undefined) {
      throw new Error("The console is not initialized.");
    }
    return auth.value;
  };

  const requireApi = (): HemligApi => {
    if (api.value === undefined) {
      throw new Error("The console is not initialized.");
    }
    return api.value;
  };

  const requireConfig = (): RuntimeConfig => {
    if (config.value === undefined) {
      throw new Error("The console is not initialized.");
    }
    return config.value;
  };

  const signIn = async (returnTo?: string): Promise<void> => {
    const driver = requireAuth();
    signedOut.value = false;
    writeSignedOut(false);
    await driver.signIn(returnTo);
  };

  /** Resolves to the session; `returnTo` is where the operator was going before sign-in. */
  const completeSignIn = async (): Promise<CompletedSession | undefined> => {
    const driver = requireAuth();
    const completed = await driver.completeSignIn();
    if (completed === undefined) {
      session.value = undefined;
      return undefined;
    }
    const { returnTo: _returnTo, ...rest } = completed;
    session.value = rest;
    signedOut.value = false;
    writeSignedOut(false);
    return completed;
  };

  /** A token with at least `minValidityMs` left, renewed first if needed. */
  const accessToken = (minValidityMs: number): Promise<string | undefined> =>
    requireAuth().accessToken(minValidityMs);

  const signOut = async (): Promise<void> => {
    const driver = requireAuth();
    // The flag goes up before the session clears, so App.vue's watcher sees
    // "signed out" and cannot start a sign-in that races the end-session redirect.
    signedOut.value = true;
    writeSignedOut(true);
    session.value = undefined;
    await driver.signOut();
  };

  const adoptSession = (value: Session | undefined): void => {
    session.value = value;
  };

  return {
    config,
    api,
    session,
    bootError,
    signedOut,
    initialize,
    requireApi,
    requireConfig,
    signIn,
    completeSignIn,
    accessToken,
    signOut,
    adoptSession,
  };
});

const ENVIRONMENT_HINT = "hemlig.console.environment";

/** A per-viewer convenience only; the environment of record is the URL. */
export const rememberEnvironment = (environment: string): void => {
  try {
    window.localStorage.setItem(ENVIRONMENT_HINT, environment);
  } catch {
    // Private windows and blocked site data are expected; the URL still wins.
  }
};

export const recallEnvironment = (): string | undefined => {
  try {
    return window.localStorage.getItem(ENVIRONMENT_HINT) ?? undefined;
  } catch {
    return undefined;
  }
};
