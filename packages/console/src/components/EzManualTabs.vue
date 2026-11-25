<script setup lang="ts" generic="T extends string">
import { nextTick, ref } from "vue";

const props = defineProps<{
  idPrefix: string;
  tabs: readonly { id: T; label: string }[];
  modelValue: T;
  label: string;
}>();
const emit = defineEmits<{ "update:modelValue": [value: T] }>();

const buttons = ref<HTMLButtonElement[]>([]);

const onKey = async (event: KeyboardEvent, index: number): Promise<void> => {
  const count = props.tabs.length;
  let next: number;
  switch (event.key) {
    case "ArrowRight":
    case "ArrowDown":
      next = (index + 1) % count;
      break;
    case "ArrowLeft":
    case "ArrowUp":
      next = (index + count - 1) % count;
      break;
    case "Home":
      next = 0;
      break;
    case "End":
      next = count - 1;
      break;
    default:
      return;
  }
  event.preventDefault();
  emit("update:modelValue", props.tabs[next]!.id);
  await nextTick();
  buttons.value[next]?.focus();
};
</script>

<template>
  <div class="flex gap-1" role="tablist" :aria-label="label">
    <button
      v-for="(tab, index) in tabs"
      :id="`${idPrefix}-tab-${tab.id}`"
      :key="tab.id"
      ref="buttons"
      type="button"
      role="tab"
      class="btn btn-sm"
      :aria-selected="modelValue === tab.id"
      :aria-controls="`${idPrefix}-panel-${tab.id}`"
      :tabindex="modelValue === tab.id ? 0 : -1"
      :class="modelValue === tab.id ? 'bg-surface-3! text-ink!' : ''"
      :data-testid="`${idPrefix}-tab-${tab.id}`"
      @click="emit('update:modelValue', tab.id)"
      @keydown="onKey($event, index)"
    >
      {{ tab.label }}
    </button>
  </div>
</template>
