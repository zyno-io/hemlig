<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ state: string }>();

// DESIGN.md "Hemlig status mapping". Status always reads as a word in a tag;
// colour is never the only signal.
const tone = computed(() => {
  switch (props.state) {
    case "ACTIVE":
    case "succeeded":
      return "tag-success";
    case "PENDING_VALUE":
    case "PENDING":
      return "tag-warning";
    case "REVOKED":
    case "FAILED":
    case "EXPIRED":
    case "failed":
      return "tag-danger";
    default:
      return "";
  }
});
</script>

<template>
  <span class="tag" :class="tone">{{ state }}</span>
</template>
