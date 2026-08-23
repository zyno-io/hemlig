import { defineStore } from "pinia";
import { ref, shallowRef } from "vue";
import { HemligApi } from "../api/client";
import type { RuntimeConfig } from "../config";
import { createAuthDriver, type AuthDriver, type Session } from "../auth/session";

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

  const initialize = async (runtime: RuntimeConfig): Promise<void> => {
    config.value = runtime;
    const driver = createAuthDriver(runtime);
    auth.value = driver;
    api.value = new HemligApi(runtime, driver);
    session.value = await driver.initialize();
  };

  const requireAuth = (): AuthDriver => {
    if (auth.value === undefined) {
      throw new Error("The console is not initialised.");
    }
    return auth.value;
  };

  const requireApi = (): HemligApi => {
    if (api.value === undefined) {
      throw new Error("The console is not initialised.");
    }
    return api.value;
  };

  const requireConfig = (): RuntimeConfig => {
    if (config.value === undefined) {
      throw new Error("The console is not initialised.");
    }
    return config.value;
  };

  const signIn = async (): Promise<void> => {
    const driver = requireAuth();
    await driver.signIn();
  };

  const completeSignIn = async (): Promise<Session | undefined> => {
    const driver = requireAuth();
    const completed = await driver.completeSignIn();
    session.value = completed;
    return completed;
  };

  const signOut = async (): Promise<void> => {
    session.value = undefined;
    const driver = requireAuth();
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
    initialize,
    requireApi,
    requireConfig,
    signIn,
    completeSignIn,
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
