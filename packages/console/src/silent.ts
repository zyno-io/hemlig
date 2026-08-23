import { UserManager, WebStorageStateStore } from "oidc-client-ts";
import { parseRuntimeConfig } from "./config";

/**
 * Entry point for silent.html only — never import the Vue app, the router,
 * or Pinia here. The identity provider redirects the hidden renewal iframe
 * back to this document just to hand tokens to a throwaway UserManager, so
 * booting the whole SPA to service that one call would be pure waste.
 */
export const runSilentRenew = async (fetchImpl?: typeof fetch): Promise<void> => {
  try {
    const doFetch = fetchImpl ?? globalThis.fetch?.bind(globalThis);
    if (doFetch === undefined) {
      return;
    }
    const response = await doFetch("/config.json", { cache: "no-store" });
    if (!response.ok) {
      return;
    }
    const config = parseRuntimeConfig(await response.json());
    if (config.auth.mode !== "oidc") {
      // The dev bridge has no provider to renew against.
      return;
    }
    const manager = new UserManager({
      authority: config.auth.authority,
      client_id: config.auth.clientId,
      redirect_uri: `${window.location.origin}/auth/callback`,
      silent_redirect_uri: `${window.location.origin}/silent.html`,
      scope: config.auth.scopes.join(" "),
      // Must match the parent's store in src/auth/session.ts. The signin state
      // is written by the window that opened this iframe, and oidc-client-ts
      // defaults to localStorage — reading the wrong store fails every renewal
      // with "no matching state", which is invisible from inside a hidden
      // iframe. Same-origin iframes share the tab's sessionStorage, so this
      // resolves to the entry the parent wrote.
      stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
    });
    await manager.signinSilentCallback();
  } catch (error) {
    // The parent window falls back to a full redirect; an unhandled
    // rejection in a hidden iframe would otherwise be invisible noise.
    console.warn("Silent renew callback failed", error);
  }
};

void runSilentRenew();
