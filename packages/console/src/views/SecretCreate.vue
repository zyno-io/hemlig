<script setup lang="ts">
import { computed, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import AclEditor from "../components/AclEditor.vue";
import MetadataFields, { type MetadataDraft } from "../components/MetadataFields.vue";
import MutationState from "../components/MutationState.vue";
import { identifier } from "../api/payload";
import type { ControlRevision } from "../api/schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

// `path` is the folder the operator was browsing when they clicked "New
// secret" (see the `?path=` query param on this route). It only seeds the
// initial draft — the field stays editable, and creating from the root
// leaves it blank rather than prefilling anything.
const props = defineProps<{ env: string; path?: string }>();
const store = useAppStore();
const router = useRouter();

const secretId = ref("");
const acl = ref<string[]>([]);
const metadata = reactive<MetadataDraft>({
  description: "",
  path: props.path ?? "",
  tags: [],
});

const idError = computed(() => {
  if (secretId.value.length === 0) {
    return "Secret ID is required.";
  }
  return !identifier.test(secretId.value)
    ? "3–64 characters: lowercase letters, digits, or hyphens, starting with a letter."
    : undefined;
});

const canSubmit = computed(() => idError.value === undefined);

const buildInput = () => ({
  secretId: secretId.value,
  environment: props.env,
  metadata: {
    ...(metadata.description.trim() ? { description: metadata.description.trim() } : {}),
    ...(metadata.path.trim() ? { path: metadata.path.trim() } : {}),
    ...(metadata.tags.filter((t) => t.key).length > 0
      ? {
          tags: Object.fromEntries(
            metadata.tags.filter((t) => t.key).map((t) => [t.key, t.value]),
          ),
        }
      : {}),
  },
  acl: acl.value.map((consumerId) => ({ consumerId, permissions: ["read" as const] })),
});

type CreateInput = ReturnType<typeof buildInput>;

const creation = useGuardedMutation<CreateInput, ControlRevision>({
  family: "secret",
  mutate: (input, key) => store.requireApi().createSecret(input, key),
  // A create cannot be retried with the same key and must not be retried with a
  // fresh one, so the only safe recovery is to look for the named secret.
  reconcile: async (input) => {
    try {
      return await store.requireApi().getSecret(input.secretId);
    } catch {
      return undefined;
    }
  },
});

const submit = async (): Promise<void> => {
  const created = await creation.submit(buildInput());
  if (created !== undefined) {
    // A secret with no payload is PENDING_VALUE and undeliverable, so the flow
    // continues straight into the payload step rather than ending here.
    await router.push({
      name: "secret-payload",
      params: { env: props.env, secretId: created.secretId },
    });
  }
};
</script>

<template>
  <div class="max-w-2xl space-y-4 text-sm">
    <div>
      <RouterLink class="text-xs text-accent hover:underline" :to="{ name: 'secrets', params: { env } }">
        ← Secrets
      </RouterLink>
      <h1 class="text-lg font-semibold">New secret in {{ env }}</h1>
      <p class="mt-1 text-ink-muted">
        Step 1 of 2. Creating a secret leaves it in PENDING_VALUE; it becomes deliverable
        once you set its first payload on the next screen.
      </p>
    </div>

    <MutationState
      :phase="creation.phase.value"
      intent="create this secret"
      @reload="creation.reset()"
    />

    <form class="space-y-4 rounded border border-line bg-surface-raised p-4" @submit.prevent="submit">
      <MetadataFields v-model="metadata">
        <template #after-path>
          <label class="block">
            <span class="text-xs text-ink-muted">Secret ID</span>
            <input
              v-model="secretId"
              required
              placeholder="database-credentials"
              class="mono mt-1 w-full rounded border border-line bg-surface px-2 py-1"
            />
            <span v-if="idError" class="text-xs text-danger">{{ idError }}</span>
            <span v-else class="text-xs text-ink-muted">
              A stable, readable ID is used for grants and audit records.
            </span>
          </label>
        </template>
      </MetadataFields>
      <AclEditor v-model="acl" :environment="env" />

      <button
        class="rounded bg-accent px-4 py-1.5 text-white disabled:opacity-50"
        :disabled="!canSubmit || creation.phase.value.kind === 'submitting'"
        type="submit"
      >
        {{ creation.phase.value.kind === "submitting" ? "Creating…" : "Create and set payload" }}
      </button>
    </form>
  </div>
</template>
