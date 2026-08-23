<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { createAuthDriver } from "../auth/session";
import { useAppStore } from "../stores/app";

const store = useAppStore();
const router = useRouter();
const error = ref<string | undefined>();

onMounted(async () => {
  try {
    const config = store.requireConfig();
    const session = await createAuthDriver(config).completeSignIn();
    store.adoptSession(session);
    await router.replace({ name: "root" });
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught);
  }
});
</script>

<template>
  <div class="mx-auto max-w-lg p-8 text-sm">
    <p v-if="!error">Completing sign-in…</p>
    <div v-else>
      <p class="font-medium text-danger">Sign-in could not be completed.</p>
      <p class="mt-2 text-ink-muted">{{ error }}</p>
    </div>
  </div>
</template>
