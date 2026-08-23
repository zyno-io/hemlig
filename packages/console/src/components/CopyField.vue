<script setup lang="ts">
import { ref } from "vue";

const props = defineProps<{ label: string; value: string; multiline?: boolean }>();
const copied = ref(false);

const copy = async (): Promise<void> => {
  await navigator.clipboard.writeText(props.value);
  copied.value = true;
  window.setTimeout(() => {
    copied.value = false;
  }, 1500);
};

const download = (): void => {
  const blob = new Blob([props.value], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `${props.label.toLowerCase().replaceAll(/[^a-z0-9]+/g, "-")}.pem`;
  anchor.click();
  URL.revokeObjectURL(url);
};
</script>

<template>
  <div>
    <div class="flex items-center justify-between gap-2">
      <span class="text-xs font-medium text-ink-muted">{{ label }}</span>
      <span class="flex gap-2">
        <button class="rounded border border-line px-2 py-0.5 text-xs" @click="copy">
          {{ copied ? "Copied" : "Copy" }}
        </button>
        <button
          v-if="multiline"
          class="rounded border border-line px-2 py-0.5 text-xs"
          @click="download"
        >
          Download
        </button>
      </span>
    </div>
    <pre
      v-if="multiline"
      class="mt-1 max-h-48 overflow-auto rounded border border-line bg-surface p-2 text-xs"
    >{{ value }}</pre>
    <p v-else class="mono mt-1 break-all text-xs">{{ value }}</p>
  </div>
</template>
