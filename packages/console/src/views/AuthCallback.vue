<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const router = useRouter();
const error = ref<string | undefined>();

onMounted(async () => {
  try {
    const session = await store.completeSignIn();
    if (session === undefined) {
      throw new Error("The identity provider did not return a session.");
    }
    await router.replace({ name: "root" });
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught);
  }
});
</script>

<template>
  <div class="page max-w-lg">
    <p v-if="!error" class="text-ink-2">Completing sign-in…</p>
    <div v-else class="notice notice-danger" role="alert">
      <p class="notice-title">Sign-in could not be completed.</p>
      <p class="mt-1">{{ error }}</p>
    </div>
  </div>
</template>
