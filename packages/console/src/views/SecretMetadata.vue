<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed, reactive, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import AclEditor from "../components/AclEditor.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import MetadataFields, {
  type MetadataDraft,
} from "../components/MetadataFields.vue";
import MutationState from "../components/MutationState.vue";
import type { ControlRevision } from "../api/schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; secretId: string }>();
const store = useAppStore();
const router = useRouter();
const route = useRoute();

const { data, error, refetch } = useQuery({
  queryKey: computed(() => ["secret", props.env, props.secretId]),
  queryFn: () => store.requireApi().getSecret(props.env, props.secretId),
});

const acl = ref<string[]>([]);
const metadata = reactive<MetadataDraft>({
  description: "",
  tags: [],
});
const loadedVersion = ref<string | undefined>();

const adopt = (revision: ControlRevision | undefined): void => {
  if (revision === undefined) {
    return;
  }
  loadedVersion.value = revision.controlVersionId;
  metadata.description = revision.metadata.description ?? "";
  metadata.tags = Object.entries(revision.metadata.tags ?? {}).map(
    ([key, value]) => ({
      id: crypto.randomUUID(),
      key,
      value,
    }),
  );
  acl.value = revision.acl.map((grant) => grant.consumerId);
};

watch(data, adopt, { immediate: true });

const removed = computed(() =>
  (data.value?.acl ?? [])
    .map((grant) => grant.consumerId)
    .filter((consumerId) => !acl.value.includes(consumerId)),
);

interface UpdateInput {
  readonly controlVersionId: string;
  readonly metadata: ControlRevision["metadata"];
  readonly acl: ControlRevision["acl"];
}

const update = useGuardedMutation<UpdateInput, ControlRevision>({
  family: "secret",
  mutate: (input, key) =>
    store
      .requireApi()
      .updateSecret(
        props.env,
        props.secretId,
        input.controlVersionId,
        { metadata: input.metadata, acl: input.acl },
        key,
      ),
  reconcile: async (input) => {
    const current = await store
      .requireApi()
      .getSecret(props.env, props.secretId);
    // A different control version than the one we sent If-Match for means our
    // write landed; the same version means it did not.
    return current.controlVersionId === input.controlVersionId
      ? undefined
      : current;
  },
});

const submit = async (): Promise<void> => {
  if (loadedVersion.value === undefined) {
    return;
  }
  const result = await update.submit({
    controlVersionId: loadedVersion.value,
    metadata: {
      ...(metadata.description.trim()
        ? { description: metadata.description.trim() }
        : {}),
      ...(metadata.tags.filter((t) => t.key).length > 0
        ? {
            tags: Object.fromEntries(
              metadata.tags.filter((t) => t.key).map((t) => [t.key, t.value]),
            ),
          }
        : {}),
    },
    acl: acl.value.map((consumerId) => ({
      consumerId,
      permissions: ["read" as const],
    })),
  });
  if (result !== undefined) {
    await router.push({
      name: "secret",
      params: { env: props.env, secretId: props.secretId },
      query: route.query,
    });
  }
};

const reload = async (): Promise<void> => {
  update.reset();
  const refreshed = await refetch();
  adopt(refreshed.data);
};
</script>

<template>
  <div class="max-w-2xl space-y-4 text-sm">
    <div>
      <RouterLink
        class="text-xs text-accent hover:underline"
        :to="{ name: 'secret', params: { env, secretId }, query: route.query }"
      >
        ← {{ secretId }}
      </RouterLink>
      <h1 class="text-lg font-semibold">Edit metadata and access</h1>
      <p class="mt-1 text-ink-muted">
        This creates a new control revision. It never decrypts the payload.
      </p>
    </div>

    <ErrorNotice v-if="error" :error="error" />
    <MutationState
      :phase="update.phase.value"
      intent="update this secret"
      @reload="reload"
    />

    <form
      v-if="data"
      class="space-y-4 rounded border border-line bg-surface-raised p-4"
      @submit.prevent="submit"
    >
      <MetadataFields v-model="metadata" />
      <AclEditor v-model="acl" :environment="env" :removed="removed" />
      <div class="flex items-center gap-3">
        <button
          class="rounded bg-accent px-4 py-1.5 text-white disabled:opacity-50"
          :disabled="update.phase.value.kind === 'submitting'"
          type="submit"
        >
          {{ update.phase.value.kind === "submitting" ? "Saving…" : "Save" }}
        </button>
        <span class="mono text-xs text-ink-muted"
          >If-Match {{ loadedVersion }}</span
        >
      </div>
    </form>
  </div>
</template>
