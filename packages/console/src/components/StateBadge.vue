<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ state: string }>();

const tone = computed(() => {
  switch (props.state) {
    case "ACTIVE":
      return "bg-ok/15 text-ok";
    case "PENDING_VALUE":
    case "PENDING":
      return "bg-warn/15 text-warn";
    case "ARCHIVED":
      return "bg-line/40 text-ink-muted";
    case "REVOKED":
    case "FAILED":
    case "EXPIRED":
      return "bg-danger/15 text-danger";
    default:
      return "bg-line/40 text-ink-muted";
  }
});
</script>

<template>
  <span class="rounded px-2 py-0.5 text-xs font-medium" :class="tone">{{
    state
  }}</span>
</template>
