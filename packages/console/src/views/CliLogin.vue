<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { confirmationCode } from "../auth/confirmationCode";
import { useAppStore } from "../stores/app";

/**
 * Hands this console's existing OIDC access token to `hemlig login`, which is
 * listening on a loopback port. The CLI never performs OAuth itself. The token
 * travels in a top-level form POST body, never in a URL and never through
 * fetch (browsers restrict fetch to local-network targets).
 */
const store = useAppStore();
const route = useRoute();

const RENEW_WITHIN_MS = 5 * 60 * 1000;
/** Authorize stays disabled this long after the page becomes visible (clickjacking guard). */
const ARM_DELAY_MS = 1500;


const single = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;

const port = computed(() => {
  const raw = single(route.query.port);
  if (raw === undefined || !/^\d{1,5}$/.test(raw)) return undefined;
  const value = Number(raw);
  return value >= 1024 && value <= 65535 ? value : undefined;
});
const state = computed(() => {
  const raw = single(route.query.state);
  return raw !== undefined && /^[A-Za-z0-9_-]{32,128}$/.test(raw) ? raw : undefined;
});
const valid = computed(() => port.value !== undefined && state.value !== undefined);
const target = computed(() => `127.0.0.1:${port.value}`);

const signedInAs = computed(
  () => store.session?.email ?? store.session?.displayName ?? store.session?.subject ?? "—",
);

const code = ref<string | undefined>();
watch(
  state,
  async (value) => {
    code.value = undefined;
    if (value !== undefined) code.value = await confirmationCode(value);
  },
  { immediate: true },
);

const armed = ref(false);
let armTimer: ReturnType<typeof setTimeout> | undefined;
const arm = (): void => {
  armed.value = false;
  clearTimeout(armTimer);
  if (document.visibilityState === "visible") {
    armTimer = setTimeout(() => {
      armed.value = true;
    }, ARM_DELAY_MS);
  }
};
onMounted(() => {
  arm();
  document.addEventListener("visibilitychange", arm);
});
onBeforeUnmount(() => {
  clearTimeout(armTimer);
  document.removeEventListener("visibilitychange", arm);
});

const phase = ref<"idle" | "sending" | "cancelled">("idle");
const error = ref<string | undefined>();

const authorize = async (): Promise<void> => {
  if (!valid.value || !armed.value || phase.value === "sending") return;
  error.value = undefined;
  phase.value = "sending";
  try {
    const token = await store.accessToken(RENEW_WITHIN_MS);
    if (token === undefined) {
      throw new Error("This console session has no access token to hand over.");
    }
    // The API this token is for; the CLI binds the cached login to it.
    const adminUrl = new URL(store.requireConfig().adminApiUrl).origin;
    const form = document.createElement("form");
    form.method = "POST";
    form.action = `http://127.0.0.1:${port.value}/callback`;
    form.enctype = "application/x-www-form-urlencoded";
    form.hidden = true;
    for (const [name, value] of [
      ["access_token", token],
      ["state", state.value!],
      ["admin_url", adminUrl],
    ] as const) {
      const input = document.createElement("input");
      input.type = "hidden";
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }
    document.body.appendChild(form);
    form.submit();
  } catch (caught) {
    phase.value = "idle";
    error.value = caught instanceof Error ? caught.message : String(caught);
  }
};

const cancel = (): void => {
  phase.value = "cancelled";
};
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">Authorize the Hemlig CLI</h1>
      </div>
    </div>

    <div class="space-y-4">
      <section v-if="!valid" class="notice notice-danger max-w-xl" role="alert">
        <p class="notice-title">This CLI sign-in link is invalid.</p>
        <p class="mt-1">
          The port or state is missing or malformed. Run <code>hemlig login</code> again.
        </p>
      </section>

      <section v-else-if="phase === 'cancelled'" class="card card-body max-w-xl">
        <p class="font-medium">Cancelled</p>
        <p class="mt-1 text-[13px] text-ink-2">Nothing was sent to the CLI.</p>
      </section>

      <section v-else class="card card-body max-w-xl">
        <h2 class="section-title">Authorize the Hemlig CLI on this computer?</h2>
        <div class="mt-3">
          <p class="text-[13px] text-ink-2">Confirmation code</p>
          <p class="mono text-2xl font-semibold tracking-wider" data-testid="confirmation-code">
            {{ code ?? "…" }}
          </p>
          <p class="mt-1 text-[13px] text-ink-2">
            Only authorize if this matches the code in your terminal.
          </p>
        </div>
        <dl class="facts mt-3">
          <dt>Target</dt>
          <dd class="mono">{{ target }}</dd>
          <dt>Signed in as</dt>
          <dd class="mono break-all">{{ signedInAs }}</dd>
        </dl>
        <p class="mt-3 text-[13px] text-ink-2">
          The token grants full administrator access until it expires.
        </p>
        <div v-if="error" class="notice notice-danger mt-3" role="alert">
          <p class="notice-title">Could not authorize the CLI.</p>
          <p class="mt-1">{{ error }}</p>
        </div>
        <div class="mt-4 flex gap-2">
          <button
            type="button"
            class="btn btn-primary"
            :disabled="phase === 'sending' || !armed || code === undefined"
            @click="authorize"
          >
            {{ phase === "sending" ? "Authorizing…" : "Authorize" }}
          </button>
          <button type="button" class="btn" :disabled="phase === 'sending'" @click="cancel">
            Cancel
          </button>
        </div>
      </section>
    </div>
  </div>
</template>
