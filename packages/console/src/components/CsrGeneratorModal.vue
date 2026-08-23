<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import CopyField from "./CopyField.vue";
import { DEFAULT_CSR_KEY_SIZE, generateCsr, type CsrKeySize, type GeneratedCsr } from "../api/csr-generate";

const props = defineProps<{
  /**
   * Prefills the common name — typically the consumer ID — but the value is
   * cosmetic. Hemlig assigns the consumer's SPIFFE URI SAN and clientAuth
   * EKU itself and ignores whatever subject a submitted CSR carries.
   */
  commonName: string;
}>();

const emit = defineEmits<{ generated: [csrPem: string]; close: [] }>();

const commonNameInput = ref(props.commonName);
const keySize = ref<CsrKeySize>(DEFAULT_CSR_KEY_SIZE);
const pending = ref(false);
const error = ref<string | undefined>();
const acknowledged = ref(false);

/**
 * Holds the only copy of the generated private key that will ever exist.
 * It lives only in this ref — never in a store, the query cache,
 * localStorage/sessionStorage/IndexedDB, a cookie, the URL, or an error
 * message — and is wiped below on both close and unmount so it cannot
 * outlive this component.
 */
const generatedCsr = ref<GeneratedCsr | undefined>();

const isCsrKeySize = (value: number): value is CsrKeySize => value === 2048 || value === 3072 || value === 4096;

// A plain @change handler, rather than v-model.number, keeps keySize typed
// as CsrKeySize instead of widening it to a bare number.
const onKeySizeChange = (event: Event): void => {
  const value = Number((event.target as HTMLSelectElement).value);
  keySize.value = isCsrKeySize(value) ? value : DEFAULT_CSR_KEY_SIZE;
};

const clear = (): void => {
  generatedCsr.value = undefined;
  acknowledged.value = false;
  error.value = undefined;
};

onUnmounted(clear);

const generate = async (): Promise<void> => {
  error.value = undefined;
  pending.value = true;
  try {
    generatedCsr.value = await generateCsr({
      commonName: commonNameInput.value.trim(),
      keySize: keySize.value,
    });
  } catch {
    // Deliberately swallow the underlying error's detail: a WebCrypto
    // exception can echo call parameters back, and this is the one surface
    // in the console that must never risk putting key material in a
    // message. See the README's "Rules that are not obvious" entry.
    error.value = "Key generation failed. Try again, or paste a CSR generated on the consumer host instead.";
  } finally {
    pending.value = false;
  }
};

const cancel = (): void => {
  clear();
  emit("close");
};

const useCsr = (): void => {
  const csr = generatedCsr.value;
  if (csr === undefined || !acknowledged.value) {
    return;
  }
  emit("generated", csr.csrPem);
  clear();
  emit("close");
};
</script>

<template>
  <div
    class="fixed inset-0 z-10 flex items-center justify-center bg-black/40 p-4"
    role="dialog"
    aria-modal="true"
    aria-labelledby="csr-generator-title"
  >
    <div class="w-full max-w-lg rounded border border-line bg-surface-raised p-5 text-sm">
      <h2 id="csr-generator-title" class="font-semibold">Generate a key pair and CSR</h2>

      <p class="mt-2 rounded bg-warn/10 p-2 text-xs text-warn">
        The private key is shown exactly once, in this browser tab only. Hemlig never
        receives it — only the CSR's public key ever leaves this page. Pasting a CSR
        generated on the consumer host is still the stronger option: it means a
        consumer's private key never exists in an administrator's browser at all.
      </p>

      <template v-if="!generatedCsr">
        <label class="mt-4 block">
          <span class="text-xs text-ink-muted">Common name</span>
          <input
            v-model="commonNameInput"
            class="mono mt-1 w-full rounded border border-line bg-surface px-2 py-1"
          />
          <span class="text-xs text-ink-muted">
            Cosmetic only — the issued identity comes from the consumer ID, not this
            field.
          </span>
        </label>

        <label class="mt-3 block">
          <span class="text-xs text-ink-muted">Key size</span>
          <select
            :value="keySize"
            class="mt-1 w-full rounded border border-line bg-surface px-2 py-1"
            @change="onKeySizeChange"
          >
            <option :value="2048">2048-bit</option>
            <option :value="3072">3072-bit (recommended)</option>
            <option :value="4096">4096-bit</option>
          </select>
        </label>

        <p v-if="error" class="mt-2 text-xs text-danger">{{ error }}</p>
        <p v-if="pending" class="mt-2 text-xs text-ink-muted">
          Generating a {{ keySize }}-bit key can take a few seconds.
        </p>

        <div class="mt-4 flex justify-end gap-2">
          <button type="button" class="rounded border border-line px-3 py-1" @click="cancel">Cancel</button>
          <button
            type="button"
            class="rounded bg-accent px-3 py-1 text-white disabled:opacity-50"
            :disabled="pending || commonNameInput.trim().length === 0"
            @click="generate"
          >
            {{ pending ? "Generating…" : "Generate" }}
          </button>
        </div>
      </template>

      <template v-else>
        <div class="mt-4 space-y-3">
          <CopyField label="Certificate signing request" :value="generatedCsr.csrPem" multiline />

          <div class="rounded border border-danger/50 bg-danger/5 p-3">
            <p class="text-xs font-medium text-danger">
              Private key — shown once and only here. Hemlig never receives this. Install
              it on the consumer host now; do not leave it sitting in a downloads folder.
            </p>
            <div class="mt-2">
              <CopyField label="Private key" :value="generatedCsr.privateKeyPem" multiline />
            </div>
          </div>

          <CopyField label="Public key fingerprint (SHA-256)" :value="generatedCsr.publicKeyFingerprint" />
        </div>

        <label class="mt-4 flex items-start gap-2 text-xs">
          <input v-model="acknowledged" type="checkbox" class="mt-0.5" />
          <span>I have saved the private key somewhere safe. It will not be shown again.</span>
        </label>

        <div class="mt-4 flex justify-end gap-2">
          <button type="button" class="rounded border border-line px-3 py-1" @click="cancel">Discard</button>
          <button
            type="button"
            class="rounded bg-accent px-3 py-1 text-white disabled:opacity-50"
            :disabled="!acknowledged"
            @click="useCsr"
          >
            Use this CSR
          </button>
        </div>
      </template>
    </div>
  </div>
</template>
