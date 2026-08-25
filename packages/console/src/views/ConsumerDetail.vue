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

interface ManagedSecretPermission {
  readonly secretId: string;
  readonly secretUid: string;
  readonly permission: "read" | "write";
}

const managedSecretPermissions = computed<readonly ManagedSecretPermission[]>(
  () => {
    const agentGrant = consumer.data.value?.agentGrant;
    if (agentGrant === undefined) {
      return grants.items.value.flatMap((grant) =>
        grant.permissions.map((permission) => ({
          secretId: grant.secretId,
          secretUid: grant.secretUid,
          permission,
        })),
      );
    }
    return agentGrant.secretGrants.flatMap((grant) =>
      grant.permissions.map((permission) => ({
        secretId: grant.secretId,
        secretUid: grant.secretUid,
        permission,
      })),
    );
  },
);

const csr = ref("");
const csrProblem = ref<string | undefined>();
const rotating = ref(false);
const showGenerator = ref(false);
const revokeTarget = ref<ApiIdentity | undefined>();
const revokeGrantTarget = ref<ManagedSecretPermission | undefined>();

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
  ManagedSecretPermission,
  AgentGrant
>({
  family: "secret",
  mutate: (target) => {
    const agentGrant = consumer.data.value?.agentGrant;
    if (agentGrant === undefined) {
      throw new Error("The consumer does not have an agent grant.");
    }
    const secretGrants = agentGrant.secretGrants.flatMap((grant) => {
      if (
        grant.secretUid !== target.secretUid ||
        !grant.permissions.includes(target.permission)
      ) {
        return [grant];
      }
      const permissions = grant.permissions.filter(
        (permission) => permission !== target.permission,
      );
      return permissions.length === 0 ? [] : [{ ...grant, permissions }];
    });
    const capabilities = agentGrant.capabilities.filter((capability) =>
      secretGrants.some((grant) => grant.permissions.includes(capability)),
    );
    return store.requireApi().updateAgentGrant(agentGrant.grantId, {
      capabilities,
      secretGrants: secretGrants.map((grant) => ({
        secretId: grant.secretId,
        permissions: grant.permissions,
      })),
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
  const result =
    consumer.data.value?.agentGrant === undefined
      ? await grantRevocation.submit(target.secretId)
      : await agentGrantRevocation.submit(target);
  if (result !== undefined) {
    if (consumer.data.value?.agentGrant === undefined) {
      reloadGrants();
    } else {
      await queryClient.invalidateQueries({ queryKey: consumerKey.value });
      reloadGrants();
    }
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
      intent="revoke this grant"
      @retry="grantRevocation.retry()"
      @reload="reloadGrants"
    />
    <MutationState
      :phase="agentGrantRevocation.phase.value"
      :can-retry="agentGrantRevocation.canRetry.value"
      intent="revoke this grant"
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
          <h2 class="font-medium">Grants</h2>
          <p
            v-if="consumer.data.value?.agentGrant"
            class="mt-1 text-xs text-ink-muted"
          >
            Canonical exact permissions from this consumer's AgentGrant. Read
            access is projected automatically into the delivery feed.
          </p>
          <p v-else class="mt-1 text-xs text-ink-muted">
            Effective secret ACL permissions for this consumer.
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
        v-if="
          grants.error.value && consumer.data.value?.agentGrant === undefined
        "
        class="mt-3"
        :error="grants.error.value"
      />

      <table
        v-else-if="managedSecretPermissions.length > 0"
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
            v-for="grant in managedSecretPermissions"
            :key="`${grant.secretUid}:${grant.permission}`"
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
            <td class="py-2 pr-3 text-xs">{{ grant.permission }}</td>
            <td class="py-2 text-right">
              <button
                class="rounded border border-danger/50 px-2 py-1 text-xs text-danger"
                :aria-label="`Revoke ${grant.permission} permission for ${grant.secretId}`"
                @click="revokeGrantTarget = grant"
              >
                Revoke
              </button>
            </td>
          </tr>
        </tbody>
      </table>
      <p
        v-else-if="
          (consumer.data.value?.agentGrant !== undefined ||
            grants.exhausted.value) &&
          !grants.loading.value
        "
        class="mt-3 rounded border border-line p-3 text-center text-xs text-ink-muted"
      >
        This consumer has no secret permissions.
      </p>

      <button
        v-if="
          consumer.data.value?.agentGrant === undefined &&
          !grants.exhausted.value &&
          managedSecretPermissions.length > 0 &&
          !grants.error.value
        "
        class="mt-3 rounded border border-line px-3 py-1 text-xs"
        :disabled="grants.loading.value"
        @click="grants.loadMore()"
      >
        {{ grants.loading.value ? "Loading…" : "Load more" }}
      </button>
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
        <h2 class="font-semibold">Revoke this permission?</h2>
        <p class="mono mt-2 break-all text-xs">
          {{ revokeGrantTarget.permission }}: {{ revokeGrantTarget.secretId }}
        </p>
        <p v-if="consumer.data.value?.agentGrant" class="mt-2 text-sm">
          This removes the exact permission from the canonical AgentGrant and
          reconciles its read delivery access automatically.
        </p>
        <p v-else class="mt-2 text-sm">
          This removes {{ consumerId }} from the secret ACL immediately and
          sends a durable delivery revocation.
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

    <CsrGeneratorModal
      v-if="showGenerator"
      :common-name="consumerId"
      @generated="onGenerated"
      @close="showGenerator = false"
    />
  </div>
</template>
