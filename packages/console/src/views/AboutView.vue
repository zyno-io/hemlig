<script setup lang="ts">
import { computed } from "vue";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const signedInAs = computed(
  () =>
    store.session?.email ??
    store.session?.displayName ??
    store.session?.subject ??
    "—",
);

const excluded = [
  [
    "Deleting a secret",
    "No delete route exists. Retirement is removing the consumer from the ACL, which leaves a REVOKED tombstone the operator acts on.",
  ],
  [
    "Rotating the issuer root",
    "Deliberately excluded until an overlap and migration protocol is reviewed.",
  ],
];
</script>

<template>
  <div class="space-y-6 text-sm">
    <section>
      <h1 class="text-lg font-semibold">About this console</h1>
      <dl class="mt-3 grid max-w-lg grid-cols-[10rem_1fr] gap-y-2">
        <dt class="text-ink-muted">Deployment (CDK stack)</dt>
        <dd class="mono">{{ store.config?.deploymentName }}</dd>
        <dt class="text-ink-muted">Administrator API</dt>
        <dd class="mono break-all">{{ store.config?.adminApiUrl }}</dd>
        <dt class="text-ink-muted">Authentication</dt>
        <dd class="mono">{{ store.config?.auth.mode }}</dd>
        <dt class="text-ink-muted">Signed in as</dt>
        <dd class="mono break-all">{{ signedInAs }}</dd>
        <template v-if="store.session?.email !== undefined">
          <dt class="text-ink-muted">OIDC subject</dt>
          <dd class="mono break-all">{{ store.session.subject }}</dd>
        </template>
      </dl>
    </section>

    <section>
      <h2 class="font-medium">Who is an administrator</h2>
      <p class="mt-1 max-w-2xl text-ink-muted">
        Hemlig has no internal user directory. The identity provider controls
        administrator assignment; the API requires its configured issuer,
        audience, scope, and optional role. This console cannot grant or
        restrict that access.
      </p>
    </section>

    <section>
      <h2 class="font-medium">Deliberately not built</h2>
      <dl class="mt-2 max-w-2xl space-y-3">
        <div v-for="[title, reason] in excluded" :key="title">
          <dt class="font-medium">{{ title }}</dt>
          <dd class="text-ink-muted">{{ reason }}</dd>
        </div>
      </dl>
    </section>

    <section>
      <h2 class="font-medium">Audit scope</h2>
      <p class="mt-1 max-w-2xl text-ink-muted">
        Mutations and secret-value revelations write audit evidence into an
        Object Lock Compliance archive that cannot be deleted for seven years.
        Routine metadata browsing does not, so the console refreshes it normally.
      </p>
    </section>
  </div>
</template>
