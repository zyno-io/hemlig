<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";

const props = defineProps<{
  title: string;
  /** The exact text the operator must type. Compared with `===`. */
  expected: string;
  confirmLabel: string;
  busy?: boolean;
}>();
const emit = defineEmits<{ confirm: []; cancel: [] }>();

const typed = ref("");
const input = ref<HTMLInputElement | undefined>();

// Case-sensitive and untrimmed on purpose: the typed name is the proof of
// intent, so near-misses must not count.
const matches = computed(() => typed.value === props.expected);
const canConfirm = computed(() => matches.value && props.busy !== true);

watch(
  () => props.expected,
  () => {
    typed.value = "";
  },
);

onMounted(() => {
  input.value?.focus();
});

const confirm = (): void => {
  if (canConfirm.value) {
    emit("confirm");
  }
};
</script>

<template>
  <div
    class="modal-scrim"
    role="dialog"
    aria-modal="true"
    aria-labelledby="typed-confirm-title"
    @keydown.esc="emit('cancel')"
  >
    <form class="modal-panel max-w-lg" @submit.prevent="confirm">
      <h2 id="typed-confirm-title" class="text-[17px] font-semibold">{{ title }}</h2>
      <div class="mt-3 space-y-2">
        <slot />
      </div>
      <label class="mt-4 block">
        <span class="field-label">
          Type <span class="mono text-ink">{{ expected }}</span> to confirm
        </span>
        <input
          ref="input"
          v-model="typed"
          class="input mono"
          autocomplete="off"
          autocapitalize="off"
          spellcheck="false"
          data-testid="typed-confirm-input"
        />
      </label>
      <div class="mt-4 flex justify-end gap-2">
        <button type="button" class="btn" data-testid="typed-confirm-cancel" @click="emit('cancel')">
          Cancel
        </button>
        <button
          type="submit"
          class="btn btn-danger"
          data-testid="typed-confirm-confirm"
          :disabled="!canConfirm"
        >
          {{ confirmLabel }}
        </button>
      </div>
    </form>
  </div>
</template>
