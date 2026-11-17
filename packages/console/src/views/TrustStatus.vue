<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import CopyField from "../components/CopyField.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import MutationState from "../components/MutationState.vue";
import { ApiError } from "../api/errors";
import type { IssuerStatus } from "../api/schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const { data, error, isFetching, refetch } = useQuery({
  queryKey: ["issuer"],
  queryFn: () => store.requireApi().getIssuer(),
});

const notEnrolled = (value: unknown): boolean =>
  value instanceof ApiError && value.code === "not_found";

const creation = useGuardedMutation<undefined, IssuerStatus>({
  // POST /v1/admin/issuer is idempotent (200 if the root already exists, 201
  // if this call created it) and replays its recorded result for a repeated
  // key, so a retry is safe with the same key — the same contract
  // useGuardedMutation's "consumer" family already encodes for enroll/rotate/
  // revoke. That family used to be named "cluster", before enrolled callers
  // were renamed to consumers (see this package's style note: consumers, not
  // clusters); useGuardedMutation.ts itself is out of scope for this change,
  // so this deliberately uses the current name rather than reintroducing the
  // old one.
  family: "consumer",
  mutate: (_input, key) => store.requireApi().createIssuer(key),
});

const createRoot = async (): Promise<void> => {
  const created = await creation.submit(undefined);
  if (created !== undefined) {
    await refetch();
  }
};

const retryCreate = async (): Promise<void> => {
  const created = await creation.retry();
  if (created !== undefined) {
    await refetch();
  }
};
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <h1 class="page-title">Trust</h1>
      </div>
      <div class="page-actions">
        <button class="btn" :disabled="isFetching" @click="refetch()">
          {{ isFetching ? "Refreshing…" : "Refresh" }}
        </button>
      </div>
    </div>

    <div v-if="notEnrolled(error)" class="card card-body">
      <p class="text-ink-2">
        No consumers have been enrolled yet. Hemlig creates its issuing root lazily, on the
        first enrollment.
      </p>
      <p class="mt-2 text-ink-2">
        Creating it now, rather than waiting, makes the root certificate available to
        distribute before anyone enrolls. The first enrollment publishes it to API Gateway.
      </p>
      <MutationState
        v-if="creation.phase.value.kind !== 'idle'"
        class="mt-3"
        :phase="creation.phase.value"
        :can-retry="creation.canRetry.value"
        intent="create the issuing root"
        @retry="retryCreate"
        @reload="creation.reset()"
      />
      <button
        class="btn mt-3"
        :disabled="creation.phase.value.kind === 'submitting'"
        @click="createRoot"
      >
        {{ creation.phase.value.kind === "submitting" ? "Creating…" : "Create issuing root" }}
      </button>
    </div>
    <ErrorNotice v-else-if="error" :error="error" />

    <div v-else-if="data" class="space-y-4">
      <section class="card card-body">
        <h2 class="section-title">Issuing root</h2>
        <div class="mt-3 space-y-3">
          <CopyField label="Root fingerprint (SHA-256)" :value="data.rootFingerprint" />
          <dl class="facts">
            <dt>Not before</dt>
            <dd class="mono">{{ data.notBefore }}</dd>
            <dt>Not after</dt>
            <dd class="mono">{{ data.notAfter }}</dd>
            <dt>Created</dt>
            <dd class="mono">{{ data.createdAt }}</dd>
          </dl>
          <CopyField label="Root certificate" :value="data.rootCertificatePem" multiline />
        </div>
      </section>

      <section class="card card-body">
        <h2 class="section-title">Published truststore</h2>
        <dl v-if="data.truststore" class="facts mt-2">
          <dt>Object key</dt>
          <dd class="mono break-all">{{ data.truststore.objectKey }}</dd>
          <dt>Version</dt>
          <dd class="mono break-all">{{ data.truststore.versionId }}</dd>
          <dt>Anchors</dt>
          <dd class="mono">{{ data.truststore.anchorCount }}</dd>
        </dl>
        <p v-else class="mt-2 text-ink-2">No bundle has been published yet.</p>
      </section>

      <p class="meta">
        Issuer-root rotation is deliberately not exposed. It requires an overlap and
        migration protocol that has not been reviewed.
      </p>
    </div>
  </div>
</template>
