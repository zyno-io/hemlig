<script setup lang="ts">
import { computed } from "vue";

const props = defineProps<{ state: string }>();

// DESIGN.md "Hemlig status mapping". Status always reads as a word in a tag;
// colour is never the only signal.
const tone = computed(() => {
  switch (props.state) {
    case "ACTIVE":
    case "succeeded":
    case "ISSUED":
    case "CURRENT":
    case "allow":
      return "tag-success";
    case "PENDING_VALUE":
    case "PENDING":
    case "PENDING_CERTIFICATE":
    case "DISABLED":
    case "STALE":
    case "MISSING":
      return "tag-warning";
    case "REVOKED":
    case "FAILED":
    case "EXPIRED":
    case "failed":
    case "CA_REVOKED":
    case "DESTROYED":
    case "deny":
      return "tag-danger";
    // RETIRED and DELETED are deliberately neutral: they are resting states.
    default:
      return "";
  }
});
</script>

<template>
  <span class="tag" :class="tone">{{ state }}</span>
</template>
