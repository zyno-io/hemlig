<script setup lang="ts">
defineProps<{
  label: string;
  modelValue: string;
  /** Validation messages keyed by zero-based line index. */
  errors: Record<number, string>;
  hint?: string;
  disabled?: boolean;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();

const onInput = (event: Event): void => {
  emit("update:modelValue", (event.target as HTMLTextAreaElement).value);
};
</script>

<template>
  <label class="block">
    <span class="field-label">{{ label }}</span>
    <textarea
      class="input mono text-xs"
      rows="3"
      spellcheck="false"
      autocomplete="off"
      :value="modelValue"
      :disabled="disabled"
      placeholder="One rule per line"
      @input="onInput"
    />
    <p v-if="hint" class="field-hint">{{ hint }}</p>
    <ul v-if="Object.keys(errors).length > 0" class="mt-1" role="alert">
      <li v-for="(message, line) in errors" :key="line" class="field-error">
        Line {{ Number(line) + 1 }}: {{ message }}
      </li>
    </ul>
  </label>
</template>
