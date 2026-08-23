<script setup lang="ts">
import { useAppStore } from "../stores/app";

const store = useAppStore();

const excluded = [
  ["Audit log", "There is no audit-query endpoint. The archive lives in a separate audit boundary with its own read role."],
  ["Deleting a secret", "No delete route exists. Retirement is removing the consumer from the ACL, which leaves a REVOKED tombstone the operator acts on."],
  ["Viewing a payload", "The administrator API never returns a decrypted payload, and this console will not grow a path to one."],
  ["Rotating the issuer root", "Deliberately excluded until an overlap and migration protocol is reviewed."],
];
</script>

<template>
  <div class="space-y-6 text-sm">
    <section>
      <h1 class="text-lg font-semibold">About this console</h1>
      <dl class="mt-3 grid max-w-lg grid-cols-[10rem_1fr] gap-y-2">
        <dt class="text-ink-muted">Deployment</dt>
        <dd class="mono">{{ store.config?.deploymentName }}</dd>
        <dt class="text-ink-muted">Administrator API</dt>
        <dd class="mono break-all">{{ store.config?.adminApiUrl }}</dd>
        <dt class="text-ink-muted">Authentication</dt>
        <dd class="mono">{{ store.config?.auth.mode }}</dd>
        <dt class="text-ink-muted">Signed in as</dt>
        <dd class="mono">{{ store.session?.subject ?? "—" }}</dd>
      </dl>
    </section>

    <section>
      <h2 class="font-medium">Who is an administrator</h2>
      <p class="mt-1 max-w-2xl text-ink-muted">
        Hemlig has no roles. Any token satisfying the configured issuer, audience, and
        scope is a full administrator, so access is decided entirely by application
        assignment in your identity provider. This console cannot grant or restrict it.
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
      <h2 class="font-medium">Why nothing auto-refreshes</h2>
      <p class="mt-1 max-w-2xl text-ink-muted">
        Every administrator request writes audit evidence into an Object Lock Compliance
        archive that cannot be deleted for seven years. Polling would write permanent
        records nobody asked for, so refreshing is always an explicit action.
      </p>
    </section>
  </div>
</template>
