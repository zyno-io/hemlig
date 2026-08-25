<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, ref, watch } from "vue";
import CopyField from "../components/CopyField.vue";
import CsrGeneratorModal from "../components/CsrGeneratorModal.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import MutationState from "../components/MutationState.vue";
import StateBadge from "../components/StateBadge.vue";
import { inspectCsr } from "../api/csr";
import type {
  AgentGrant,
  ApiIdentity,
  ApiIdentityResult,
  ConsumerSecretGrant,
  ControlRevision,
} from "../api/schemas";
import { useCursorPages } from "../composables/useCursorPages";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; consumerId: string }>();
const store = useAppStore();
const queryClient = useQueryClient();

const consumerKey = computed(() => ["consumer", props.consumerId]);
const identitiesKey = computed(() => ["consumer-identities", props.consumerId]);

const consumer = useQuery({
  queryKey: consumerKey,
  queryFn: () => store.requireApi().getConsumer(props.consumerId),
});
const identities = useQuery({
  queryKey: identitiesKey,
  queryFn: () => store.requireApi().listApiIdentities(props.consumerId),
});
const grants = useCursorPages<ConsumerSecretGrant>(async (cursor) => {
  const page = await store
    .requireApi()
    .listConsumerSecretGrants(props.consumerId, cursor);
  return { items: page.grants, nextCursor: page.nextCursor };
});

const expired = (identity: ApiIdentity): boolean =>
  new Date(identity.notAfter).getTime() <= Date.now();
const expiringSoon = (identity: ApiIdentity): boolean => {
  const remaining = new Date(identity.notAfter).getTime() - Date.now();
  return remaining > 0 && remaining < 30 * 24 * 60 * 60 * 1000;
};
// The API never writes EXPIRED; expiry is evaluated against notAfter.
const displayStatus = (identity: ApiIdentity): string =>
  identity.status === "ACTIVE" && expired(identity)
    ? "EXPIRED"
    : identity.status;

const activeCount = computed(
  () =>
    (identities.data.value?.apiIdentities ?? []).filter(
      (identity) => identity.status === "ACTIVE" && !expired(identity),
    ).length,
);

interface AgentSecretPermission {
  readonly secretId: string;
  readonly secretUid?: string;
  readonly permission: "read" | "write";
}

const agentSecretPermissions = computed<readonly AgentSecretPermission[]>(
  () => {
    const agentGrant = consumer.data.value?.agentGrant;
    if (agentGrant === undefined) {
      return [];
    }
    return [
      ...agentGrant.readSecretIds.map((secretId, index) => ({
        secretId,
        secretUid: agentGrant.readSecretUids[index],
        permission: "read" as const,
      })),
      ...agentGrant.writeSecretIds.map((secretId, index) => ({
        secretId,
        secretUid: agentGrant.writeSecretUids[index],
        permission: "write" as const,
      })),
    ];
  },
);

const csr = ref("");
const csrProblem = ref<string | undefined>();
const rotating = ref(false);
const showGenerator = ref(false);
const revokeTarget = ref<ApiIdentity | undefined>();
const revokeGrantTarget = ref<ConsumerSecretGrant | undefined>();
const revokeAgentPermissionTarget = ref<AgentSecretPermission | undefined>();

// Pasting an operator-generated CSR remains the default, primary path; this
// only fills the same textarea the paste/upload flow already validates.
const onGenerated = (csrPem: string): void => {
  csr.value = csrPem;
  csrProblem.value = undefined;
};

const rotation = useGuardedMutation<string, ApiIdentityResult>({
  family: "consumer",
  mutate: (pem, key) =>
    store.requireApi().rotateApiIdentity(props.consumerId, pem, key),
});
const revocation = useGuardedMutation<string, ApiIdentityResult>({
  family: "consumer",
  mutate: (fingerprint, key) =>
    store.requireApi().revokeApiIdentity(props.consumerId, fingerprint, key),
});
const grantRevocation = useGuardedMutation<string, ControlRevision>({
  family: "secret",
  mutate: (secretId, key) =>
    store
      .requireApi()
      .revokeConsumerSecretGrant(props.consumerId, secretId, key),
});
const agentGrantRevocation = useGuardedMutation<
  AgentSecretPermission,
  AgentGrant
>({
  family: "secret",
  mutate: (target) => {
    const agentGrant = consumer.data.value?.agentGrant;
    if (agentGrant === undefined) {
      throw new Error("The consumer does not have an agent grant.");
    }
    return store.requireApi().updateAgentGrant(agentGrant.grantId, {
      capabilities: agentGrant.capabilities,
      readSecretIds:
        target.permission === "read"
          ? agentGrant.readSecretIds.filter(
              (secretId) => secretId !== target.secretId,
            )
          : agentGrant.readSecretIds,
      writeSecretIds:
        target.permission === "write"
          ? agentGrant.writeSecretIds.filter(
              (secretId) => secretId !== target.secretId,
            )
          : agentGrant.writeSecretIds,
      ...(agentGrant.displayName === undefined
        ? {}
        : { displayName: agentGrant.displayName }),
    });
  },
});

const reloadGrants = (): void => {
  grants.reset();
  void grants.loadMore();
};

const refresh = (): void => {
  void consumer.refetch();
  void identities.refetch();
  reloadGrants();
};

watch(() => props.consumerId, reloadGrants, { immediate: true });

const submitRotation = async (): Promise<void> => {
  const problem = await inspectCsr(csr.value);
  csrProblem.value = problem?.message;
  if (problem !== undefined) {
    return;
  }
  const result = await rotation.submit(csr.value.trim());
  if (result !== undefined) {
    csr.value = "";
    rotating.value = false;
    await queryClient.invalidateQueries({ queryKey: identitiesKey.value });
  }
};

const confirmRevoke = async (): Promise<void> => {
  const target = revokeTarget.value;
  if (target === undefined) {
    return;
  }
  revokeTarget.value = undefined;
  const result = await revocation.submit(target.apiFingerprint);
  if (result !== undefined) {
    await queryClient.invalidateQueries({ queryKey: identitiesKey.value });
  }
};

const confirmGrantRevoke = async (): Promise<void> => {
  const target = revokeGrantTarget.value;
  if (target === undefined) {
    return;
  }
  revokeGrantTarget.value = undefined;
  const result = await grantRevocation.submit(target.secretId);
  if (result !== undefined) {
    reloadGrants();
  }
};

const confirmAgentPermissionRevoke = async (): Promise<void> => {
  const target = revokeAgentPermissionTarget.value;
  if (target === undefined) {
    return;
  }
  revokeAgentPermissionTarget.value = undefined;
  const result = await agentGrantRevocation.submit(target);
  if (result !== undefined) {
    await queryClient.invalidateQueries({ queryKey: consumerKey.value });
  }
};
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex items-center justify-between">
      <div>
        <RouterLink
          class="text-xs text-accent hover:underline"
          :to="{ name: 'consumers', params: { env } }"
        >
          ← Consumers
        </RouterLink>
        <h1 class="mono text-lg font-semibold">{{ consumerId }}</h1>
      </div>
      <button class="rounded border border-line px-3 py-1" @click="refresh">
        Refresh
      </button>
    </div>

    <ErrorNotice v-if="consumer.error.value" :error="consumer.error.value" />

    <section
      v-if="consumer.data.value"
      class="rounded border border-line bg-surface-raised p-4"
    >
      <dl class="grid grid-cols-[10rem_1fr] gap-y-1 text-xs">
        <dt class="text-ink-muted">Status</dt>
        <dd><StateBadge :state="consumer.data.value.status" /></dd>
        <dt class="text-ink-muted">Environment</dt>
        <dd class="mono">{{ consumer.data.value.environment }}</dd>
        <dt class="text-ink-muted">SPIFFE identity</dt>
        <dd class="mono break-all">{{ consumer.data.value.subjectUri }}</dd>
        <dt class="text-ink-muted">Enrolled</dt>
        <dd class="mono">{{ consumer.data.value.createdAt }}</dd>
        <dt v-if="consumer.data.value.rootFingerprint" class="text-ink-muted">
          Root fingerprint
        </dt>
        <dd v-if="consumer.data.value.rootFingerprint" class="mono break-all">
          {{ consumer.data.value.rootFingerprint }}
        </dd>
      </dl>
    </section>

    <MutationState
      :phase="rotation.phase.value"
      :can-retry="rotation.canRetry.value"
      intent="sign a new client certificate"
      @retry="rotation.retry()"
      @reload="identities.refetch()"
    />
    <MutationState
      :phase="revocation.phase.value"
      :can-retry="revocation.canRetry.value"
      intent="revoke this identity"
      @retry="revocation.retry()"
      @reload="identities.refetch()"
    />
    <MutationState
      :phase="grantRevocation.phase.value"
      :can-retry="grantRevocation.canRetry.value"
      intent="revoke this secret access grant"
      @retry="grantRevocation.retry()"
      @reload="reloadGrants"
    />
    <MutationState
      :phase="agentGrantRevocation.phase.value"
      :can-retry="agentGrantRevocation.canRetry.value"
      intent="revoke this agent policy permission"
      @retry="agentGrantRevocation.retry()"
      @reload="consumer.refetch()"
    />

    <div
      v-if="
        rotation.phase.value.kind === 'succeeded' &&
        rotation.result.value?.apiCertificatePem
      "
      class="rounded border border-ok/50 bg-ok/5 p-4"
    >
      <p class="font-medium text-ok">
        New certificate issued. This is shown once.
      </p>
      <div class="mt-3 space-y-3">
        <CopyField
          label="Leaf fingerprint"
          :value="rotation.result.value.apiFingerprint"
        />
        <CopyField
          label="Client certificate"
          :value="rotation.result.value.apiCertificatePem"
          multiline
        />
      </div>
    </div>

    <section class="rounded border border-line bg-surface-raised p-4">
      <div class="flex items-center justify-between">
        <h2 class="font-medium">API identities</h2>
        <button
          class="rounded border border-line px-3 py-1 text-xs"
          @click="rotating = !rotating"
        >
          Rotate leaf
        </button>
      </div>

      <div v-if="rotating" class="mt-3 rounded border border-line p-3">
        <p class="text-xs text-ink-muted">
          Rotation is additive: the new leaf becomes active alongside the
          current one, so distribute it before revoking anything.
        </p>
        <textarea
          v-model="csr"
          rows="6"
          spellcheck="false"
          placeholder="-----BEGIN CERTIFICATE REQUEST-----"
          class="mono mt-2 w-full rounded border border-line bg-surface px-2 py-1 text-xs"
        />
        <button
          type="button"
          class="mt-2 rounded border border-line px-2 py-1 text-xs"
          @click="showGenerator = true"
        >
          Generate key and CSR
        </button>
        <p v-if="csrProblem" class="mt-1 text-xs text-danger">
          {{ csrProblem }}
        </p>
        <button
          class="mt-2 rounded bg-accent px-3 py-1 text-white disabled:opacity-50"
          :disabled="rotation.phase.value.kind === 'submitting'"
          @click="submitRotation"
        >
          {{
            rotation.phase.value.kind === "submitting"
              ? "Signing…"
              : "Sign certificate"
          }}
        </button>
      </div>

      <ErrorNotice
        v-if="identities.error.value"
        class="mt-3"
        :error="identities.error.value"
      />

      <table
        v-else-if="identities.data.value"
        class="mt-3 w-full border-collapse text-left"
      >
        <thead class="text-xs uppercase tracking-wide text-ink-muted">
          <tr class="border-b border-line">
            <th class="py-2 pr-3 font-medium">Fingerprint</th>
            <th class="py-2 pr-3 font-medium">Status</th>
            <th class="py-2 pr-3 font-medium">Valid until</th>
            <th class="py-2 font-medium"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="identity in identities.data.value.apiIdentities"
            :key="identity.apiFingerprint"
            class="border-b border-line/60"
          >
            <td class="mono py-2 pr-3 text-xs break-all">
              {{ identity.apiFingerprint }}
            </td>
            <td class="py-2 pr-3">
              <StateBadge :state="displayStatus(identity)" />
            </td>
            <td class="mono py-2 pr-3 text-xs">
              {{ identity.notAfter }}
              <span
                v-if="expiringSoon(identity)"
                class="ml-1 rounded bg-warn/15 px-1.5 py-0.5 text-warn"
                >soon</span
              >
            </td>
            <td class="py-2 text-right">
              <button
                v-if="identity.status === 'ACTIVE'"
                class="rounded border border-danger/50 px-2 py-1 text-xs text-danger"
                @click="revokeTarget = identity"
              >
                Revoke
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <section class="rounded border border-line bg-surface-raised p-4">
      <div class="flex items-center justify-between">
        <div>
          <h2 class="font-medium">Secret access</h2>
          <p class="mt-1 text-xs text-ink-muted">
            Effective read grants for this consumer. Revoke removes the consumer
            from the secret ACL and publishes a durable delivery revocation.
          </p>
        </div>
        <button
          class="rounded border border-line px-3 py-1 text-xs"
          :disabled="grants.loading.value"
          @click="reloadGrants"
        >
          {{ grants.loading.value ? "Loading…" : "Refresh" }}
        </button>
      </div>

      <ErrorNotice
        v-if="grants.error.value"
        class="mt-3"
        :error="grants.error.value"
      />

      <table
        v-else-if="grants.items.value.length > 0"
        class="mt-3 w-full border-collapse text-left"
      >
        <thead class="text-xs uppercase tracking-wide text-ink-muted">
          <tr class="border-b border-line">
            <th class="py-2 pr-3 font-medium">Secret</th>
            <th class="py-2 pr-3 font-medium">Permission</th>
            <th class="py-2 pr-3 font-medium">State</th>
            <th class="py-2 font-medium"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="grant in grants.items.value"
            :key="grant.secretUid"
            class="border-b border-line/60"
          >
            <td class="py-2 pr-3">
              <RouterLink
                class="mono text-xs text-accent hover:underline"
                :to="{
                  name: 'secret',
                  params: { env, secretId: grant.secretId },
                }"
                >{{ grant.secretId }}</RouterLink
              >
              <div class="mono mt-0.5 text-[0.65rem] text-ink-muted">
                {{ grant.secretUid }}
              </div>
            </td>
            <td class="py-2 pr-3 text-xs">
              {{ grant.permissions.join(", ") }}
            </td>
            <td class="py-2 pr-3"><StateBadge :state="grant.state" /></td>
            <td class="py-2 text-right">
              <button
                class="rounded border border-danger/50 px-2 py-1 text-xs text-danger"
                :aria-label="`Revoke access to ${grant.secretId}`"
                @click="revokeGrantTarget = grant"
              >
                Revoke
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <p
        v-else-if="grants.exhausted.value && !grants.loading.value"
        class="mt-3 rounded border border-line p-3 text-center text-xs text-ink-muted"
      >
        This consumer has no effective secret access grants.
      </p>

      <button
        v-if="
          !grants.exhausted.value &&
          grants.items.value.length > 0 &&
          !grants.error.value
        "
        class="mt-3 rounded border border-line px-3 py-1 text-xs"
        :disabled="grants.loading.value"
        @click="grants.loadMore()"
      >
        {{ grants.loading.value ? "Loading…" : "Load more" }}
      </button>
    </section>

    <section
      v-if="consumer.data.value?.agentGrant"
      class="rounded border border-line bg-surface-raised p-4"
    >
      <div>
        <h2 class="font-medium">Agent policy</h2>
        <p class="mt-1 text-xs text-ink-muted">
          Exact per-secret permissions in AgentGrant
          <span class="mono">{{ consumer.data.value.agentGrant.grantId }}</span
          >. Revoking one permission leaves the secret ACL and any other
          permission unchanged.
        </p>
      </div>

      <table
        v-if="agentSecretPermissions.length > 0"
        class="mt-3 w-full border-collapse text-left"
      >
        <thead class="text-xs uppercase tracking-wide text-ink-muted">
          <tr class="border-b border-line">
            <th class="py-2 pr-3 font-medium">Secret</th>
            <th class="py-2 pr-3 font-medium">Permission</th>
            <th class="py-2 font-medium"></th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="grant in agentSecretPermissions"
            :key="`${grant.permission}:${grant.secretUid ?? grant.secretId}`"
            class="border-b border-line/60"
          >
            <td class="py-2 pr-3">
              <div class="mono text-xs">{{ grant.secretId }}</div>
              <div
                v-if="grant.secretUid"
                class="mono mt-0.5 text-[0.65rem] text-ink-muted"
              >
                {{ grant.secretUid }}
              </div>
            </td>
            <td class="py-2 pr-3 text-xs">{{ grant.permission }}</td>
            <td class="py-2 text-right">
              <button
                class="rounded border border-danger/50 px-2 py-1 text-xs text-danger"
                :aria-label="`Revoke ${grant.permission} permission for ${grant.secretId}`"
                @click="revokeAgentPermissionTarget = grant"
              >
                Revoke
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <p
        v-else
        class="mt-3 rounded border border-line p-3 text-center text-xs text-ink-muted"
      >
        This AgentGrant currently has no secret permissions.
      </p>
    </section>

    <div
      v-if="revokeTarget"
      class="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div
        class="w-full max-w-md rounded border border-line bg-surface-raised p-5"
      >
        <h2 class="font-semibold">Revoke this client certificate?</h2>
        <p class="mono mt-2 break-all text-xs">
          {{ revokeTarget.apiFingerprint }}
        </p>
        <p class="mt-2 text-sm">
          Revocation takes effect immediately. The delivery API reads the
          identity strongly consistently on every request, so it does not wait
          for truststore propagation.
        </p>
        <p
          v-if="activeCount <= 1"
          class="mt-2 rounded bg-danger/10 p-2 text-sm text-danger"
        >
          This is the last active identity for {{ consumerId }}. Revoking it
          stops the consumer from reading any secret until a new leaf is issued
          and installed.
        </p>
        <p v-else class="mt-2 text-xs text-ink-muted">
          {{ activeCount - 1 }} other active identit{{
            activeCount - 1 === 1 ? "y" : "ies"
          }}
          will remain.
        </p>
        <div class="mt-4 flex justify-end gap-2">
          <button
            class="rounded border border-line px-3 py-1"
            @click="revokeTarget = undefined"
          >
            Cancel
          </button>
          <button
            class="rounded bg-danger px-3 py-1 text-white"
            @click="confirmRevoke"
          >
            Revoke
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="revokeGrantTarget"
      class="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div
        class="w-full max-w-md rounded border border-line bg-surface-raised p-5"
      >
        <h2 class="font-semibold">Revoke this secret grant?</h2>
        <p class="mono mt-2 break-all text-xs">
          {{ revokeGrantTarget.secretId }}
        </p>
        <p class="mt-2 text-sm">
          This removes {{ consumerId }} from the secret ACL immediately and
          sends a durable revocation to the consumer's delivery feed.
        </p>
        <div class="mt-4 flex justify-end gap-2">
          <button
            class="rounded border border-line px-3 py-1"
            @click="revokeGrantTarget = undefined"
          >
            Cancel
          </button>
          <button
            class="rounded bg-danger px-3 py-1 text-white"
            @click="confirmGrantRevoke"
          >
            Revoke
          </button>
        </div>
      </div>
    </div>

    <div
      v-if="revokeAgentPermissionTarget"
      class="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4"
      role="dialog"
      aria-modal="true"
    >
      <div
        class="w-full max-w-md rounded border border-line bg-surface-raised p-5"
      >
        <h2 class="font-semibold">Revoke this agent policy permission?</h2>
        <p class="mono mt-2 break-all text-xs">
          {{ revokeAgentPermissionTarget.permission }}:
          {{ revokeAgentPermissionTarget.secretId }}
        </p>
        <p class="mt-2 text-sm">
          This removes only this exact permission from the AgentGrant. It does
          not change the secret ACL or any other permission for this secret.
        </p>
        <div class="mt-4 flex justify-end gap-2">
          <button
            class="rounded border border-line px-3 py-1"
            @click="revokeAgentPermissionTarget = undefined"
          >
            Cancel
          </button>
          <button
            class="rounded bg-danger px-3 py-1 text-white"
            @click="confirmAgentPermissionRevoke"
          >
            Revoke
          </button>
        </div>
      </div>
    </div>

    <CsrGeneratorModal
      v-if="showGenerator"
      :common-name="consumerId"
      @generated="onGenerated"
      @close="showGenerator = false"
    />
  </div>
</template>
