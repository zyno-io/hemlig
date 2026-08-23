<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import CopyField from "../components/CopyField.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import { ApiError } from "../api/errors";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const { data, error, isFetching, refetch } = useQuery({
  queryKey: ["issuer"],
  queryFn: () => store.requireApi().getIssuer(),
});

const notEnrolled = (value: unknown): boolean =>
  value instanceof ApiError && value.code === "not_found";
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex items-center justify-between">
      <h1 class="text-lg font-semibold">Trust</h1>
      <button
        class="rounded border border-line px-3 py-1"
        :disabled="isFetching"
        @click="refetch()"
      >
        {{ isFetching ? "Refreshing…" : "Refresh" }}
      </button>
    </div>

    <p v-if="notEnrolled(error)" class="rounded border border-line bg-surface-raised p-4 text-ink-muted">
      No consumers have been enrolled yet. Hemlig creates its issuing root lazily, on the
      first enrollment.
    </p>
    <ErrorNotice v-else-if="error" :error="error" />

    <div v-else-if="data" class="space-y-4">
      <section class="rounded border border-line bg-surface-raised p-4">
        <h2 class="font-medium">Issuing root</h2>
        <div class="mt-3 space-y-3">
          <CopyField label="Root fingerprint (SHA-256)" :value="data.rootFingerprint" />
          <dl class="grid grid-cols-[9rem_1fr] gap-y-1 text-xs">
            <dt class="text-ink-muted">Not before</dt>
            <dd class="mono">{{ data.notBefore }}</dd>
            <dt class="text-ink-muted">Not after</dt>
            <dd class="mono">{{ data.notAfter }}</dd>
            <dt class="text-ink-muted">Created</dt>
            <dd class="mono">{{ data.createdAt }}</dd>
          </dl>
          <CopyField label="Root certificate" :value="data.rootCertificatePem" multiline />
        </div>
      </section>

      <section class="rounded border border-line bg-surface-raised p-4">
        <h2 class="font-medium">Published truststore</h2>
        <dl v-if="data.truststore" class="mt-2 grid grid-cols-[9rem_1fr] gap-y-1 text-xs">
          <dt class="text-ink-muted">Object key</dt>
          <dd class="mono break-all">{{ data.truststore.objectKey }}</dd>
          <dt class="text-ink-muted">Version</dt>
          <dd class="mono break-all">{{ data.truststore.versionId }}</dd>
          <dt class="text-ink-muted">Anchors</dt>
          <dd class="mono">{{ data.truststore.anchorCount }}</dd>
        </dl>
        <p v-else class="mt-2 text-ink-muted">No bundle has been published yet.</p>
      </section>

      <p class="text-xs text-ink-muted">
        Issuer-root rotation is deliberately not exposed. It requires an overlap and
        migration protocol that has not been reviewed.
      </p>
    </div>
  </div>
</template>
