<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed } from "vue";
import type { ConsumerSummary } from "../api/schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{ environment: string; removed?: readonly string[] }>();
const model = defineModel<string[]>({ required: true });
const store = useAppStore();

const { data, error } = useQuery({
  queryKey: computed(() => ["consumers", props.environment]),
  queryFn: () => store.requireApi().listConsumers({ environment: props.environment }),
});

// Only an enrolled, active consumer in the same environment can hold a grant,
// so the picker asks the service rather than encoding that rule here.
const selectable = computed(() =>
  (data.value?.consumers ?? []).filter(
    (consumer: ConsumerSummary) => consumer.status === "ACTIVE",
  ),
);

const toggle = (consumerId: string): void => {
  model.value = model.value.includes(consumerId)
    ? model.value.filter((id) => id !== consumerId)
    : [...model.value, consumerId];
};
</script>

<template>
  <div>
    <div class="flex items-baseline justify-between">
      <span class="text-xs text-ink-muted">Consumers with read access ({{ model.length }} of 40)</span>
    </div>

    <p v-if="error" class="mt-2 text-xs text-danger">
      The consumer list could not be loaded, so grants cannot be edited safely.
    </p>
    <p v-else-if="selectable.length === 0" class="mt-2 text-xs text-ink-muted">
      No active consumers are enrolled in {{ environment }}.
    </p>

    <ul v-else class="mt-2 space-y-1">
      <li v-for="consumer in selectable" :key="consumer.consumerId">
        <label class="flex items-center gap-2 text-sm">
          <input
            type="checkbox"
            :checked="model.includes(consumer.consumerId)"
            :disabled="!model.includes(consumer.consumerId) && model.length >= 40"
            @change="toggle(consumer.consumerId)"
          />
          <span class="mono">{{ consumer.consumerId }}</span>
        </label>
      </li>
    </ul>

    <div v-if="removed && removed.length > 0" class="mt-3 rounded bg-warn/10 p-2 text-xs text-warn">
      <p class="font-medium">
        Removing {{ removed.join(", ") }} does not delete anything on the consumer.
      </p>
      <p class="mt-1">
        Each removed consumer receives a REVOKED tombstone on its next reconciliation. The
        operator must delete the corresponding Kubernetes Secret.
      </p>
    </div>
  </div>
</template>
