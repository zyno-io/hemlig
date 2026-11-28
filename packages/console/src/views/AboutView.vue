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
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">About this console</h1>
      </div>
    </div>

    <div class="space-y-4">
      <section class="card card-body">
        <dl class="facts">
          <dt>Deployment (CDK stack)</dt>
          <dd class="mono">{{ store.config?.deploymentName }}</dd>
          <dt>Administrator API</dt>
          <dd class="mono break-all">{{ store.config?.adminApiUrl }}</dd>
          <dt>Authentication</dt>
          <dd class="mono">{{ store.config?.auth.mode }}</dd>
          <dt>Signed in as</dt>
          <dd class="mono break-all">{{ signedInAs }}</dd>
          <template v-if="store.session?.email !== undefined">
            <dt>OIDC subject</dt>
            <dd class="mono break-all">{{ store.session.subject }}</dd>
          </template>
        </dl>
      </section>

      <section class="card card-body">
        <h2 class="section-title">Who is an administrator</h2>
        <p class="mt-1 max-w-2xl text-[13px] text-ink-2">
          Hemlig has no internal user directory. The identity provider controls
          administrator assignment; the API requires its configured issuer,
          audience, admin scope, and, when one is configured, the admin role
          claim. This console cannot grant or restrict that access.
        </p>
      </section>

      <section class="card card-body">
        <h2 class="section-title">Deliberately not built</h2>
        <dl class="mt-2 max-w-2xl space-y-3 text-[13px]">
          <div v-for="[title, reason] in excluded" :key="title">
            <dt class="font-medium">{{ title }}</dt>
            <dd class="text-ink-2">{{ reason }}</dd>
          </div>
        </dl>
      </section>

      <section class="card card-body">
        <h2 class="section-title">Audit scope</h2>
        <p class="mt-1 max-w-2xl text-[13px] text-ink-2">
          Mutations and secret-value revelations write audit evidence into an
          Object Lock Compliance archive that cannot be deleted for seven years.
          Routine metadata browsing does not, so the console refreshes it normally.
        </p>
      </section>
    </div>
  </div>
</template>
