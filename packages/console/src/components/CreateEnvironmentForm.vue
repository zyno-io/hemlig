<script setup lang="ts">
import { computed, ref } from "vue";
import { useRouter } from "vue-router";
import ErrorNotice from "./ErrorNotice.vue";
import { environmentName } from "../api/payload";
import { ApiError } from "../api/errors";
import type { EnvironmentDefinition } from "../api/schemas";
import { useInvalidateEnvironments } from "../composables/useEnvironments";
import { rememberEnvironment, useAppStore } from "../stores/app";

/**
 * Shared by the first-run panel (`RootResolver.vue`) and the `/environments`
 * management view, so the create flow — validation, the conflict affordance,
 * cache invalidation — exists in exactly one place.
 */
const props = withDefaults(defineProps<{ navigateOnCreate?: boolean }>(), {
  navigateOnCreate: true,
});
const emit = defineEmits<{ created: [environment: EnvironmentDefinition] }>();

const store = useAppStore();
const router = useRouter();
const invalidate = useInvalidateEnvironments();

const name = ref("");
const submitting = ref(false);
const error = ref<ApiError | undefined>();
/** Set only once a conflict is confirmed benign; see `submit` below. */
const conflictName = ref<string | undefined>();

const nameError = computed(() => {
  if (name.value.length === 0) {
    return undefined;
  }
  // Mirrors assertEnvironmentName in src/domain/validation.ts, for fast
  // feedback only — the server remains the authority on this rule.
  return environmentName.test(name.value)
    ? undefined
    : "1-64 lowercase letters, numbers, or hyphens, starting with a letter.";
});

const canSubmit = computed(
  () => name.value.length > 0 && nameError.value === undefined && !submitting.value,
);

const goToEnvironment = async (target: string): Promise<void> => {
  rememberEnvironment(target);
  await router.push({ name: "secrets", params: { env: target } });
};

const submit = async (): Promise<void> => {
  if (!canSubmit.value) {
    return;
  }
  const requested = name.value.trim();
  submitting.value = true;
  error.value = undefined;
  conflictName.value = undefined;
  try {
    const created = await store.requireApi().createEnvironment(requested);
    await invalidate();
    name.value = "";
    emit("created", created);
    if (props.navigateOnCreate) {
      await goToEnvironment(created.name);
    }
  } catch (caught) {
    if (caught instanceof ApiError && caught.code === "conflict") {
      // The registry's create condition cannot be satisfied twice for the
      // same name, so the operator's desired end state — an environment
      // named this existing — is already true. That is not a failure to
      // report; it is a nudge toward the environment that is already there.
      conflictName.value = requested;
      await invalidate();
    } else {
      error.value =
        caught instanceof ApiError
          ? caught
          : new ApiError(0, "network", "The request did not reach Hemlig.");
    }
  } finally {
    submitting.value = false;
  }
};

const switchToConflict = async (): Promise<void> => {
  if (conflictName.value !== undefined) {
    await goToEnvironment(conflictName.value);
  }
};
</script>

<template>
  <form class="space-y-4" @submit.prevent="submit">
    <!-- flex-col, not `block`: a `block` label leaves the inline <span> and a
         width-constrained input on the same line, jammed together. -->
    <label class="flex max-w-xs flex-col gap-1">
      <span class="text-xs text-ink-muted">Environment name</span>
      <input
        v-model="name"
        required
        placeholder="staging"
        class="mono w-full rounded border border-line bg-surface px-2 py-1"
      />
      <span v-if="nameError" class="text-xs text-danger">{{ nameError }}</span>
    </label>

    <p v-if="conflictName" class="rounded border border-accent/40 bg-accent/5 p-3 text-xs">
      <span class="font-medium">{{ conflictName }}</span> already exists.
      <button type="button" class="text-accent underline" @click="switchToConflict">
        Switch to it
      </button>
    </p>
    <ErrorNotice v-else-if="error" :error="error" context="creating this environment" />

    <button
      class="rounded bg-accent px-3 py-1.5 text-white disabled:opacity-50"
      type="submit"
      :disabled="!canSubmit"
    >
      {{ submitting ? "Creating…" : "Create environment" }}
    </button>
  </form>
</template>
