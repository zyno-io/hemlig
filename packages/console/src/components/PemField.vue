<script setup lang="ts">
import { ref } from "vue";
import { fileToPemOrBase64, inspectPem, type PemKind } from "../api/pki-format";

const props = defineProps<{
  label: string;
  modelValue: string;
  kind: PemKind;
  rows?: number;
  required?: boolean;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();

const problems = ref<readonly string[]>([]);
const rejectedKey = ref(false);

const KIND_HINT: Record<PemKind, string> = {
  certificate: "one PEM certificate",
  chain: "one or more PEM certificates",
  csr: "a PEM certificate request",
  crl: "a PEM X509 CRL or base64 DER",
};

/**
 * A private key never reaches the model: it is cleared here, before any
 * request could include it, and the operator is told it was not sent.
 */
const accept = (text: string): boolean => {
  if (inspectPem(text, props.kind).privateKey) {
    rejectedKey.value = true;
    problems.value = [];
    emit("update:modelValue", "");
    return false;
  }
  rejectedKey.value = false;
  emit("update:modelValue", text);
  return true;
};

const onInput = (event: Event): void => {
  const target = event.target as HTMLTextAreaElement;
  if (!accept(target.value)) {
    target.value = "";
  }
};

const onBlur = (): void => {
  problems.value =
    props.modelValue.trim() === "" ? [] : inspectPem(props.modelValue, props.kind).problems;
};

const onFile = async (event: Event): Promise<void> => {
  const target = event.target as HTMLInputElement;
  const file = target.files?.[0];
  if (file === undefined) {
    return;
  }
  const result = await fileToPemOrBase64(file, props.kind);
  target.value = "";
  if (result.problem !== undefined) {
    if (result.problem.includes("private key")) {
      rejectedKey.value = true;
      problems.value = [];
      emit("update:modelValue", "");
    } else {
      problems.value = [result.problem];
    }
    return;
  }
  if (accept(result.text)) {
    problems.value = inspectPem(result.text, props.kind).problems;
  }
};
</script>

<template>
  <div>
    <label class="block">
      <span class="field-label">{{ label }}</span>
      <textarea
        class="input mono"
        :rows="rows ?? 6"
        :value="modelValue"
        :required="required"
        spellcheck="false"
        autocomplete="off"
        :placeholder="`Paste ${KIND_HINT[kind]}`"
        @input="onInput"
        @blur="onBlur"
      />
    </label>
    <div class="mt-1 flex items-center gap-2">
      <input
        type="file"
        :aria-label="`${label} file`"
        @change="onFile"
      />
    </div>
    <p v-if="rejectedKey" class="notice notice-danger mt-2" role="alert">
      That was a private key. It was removed and is not sent. Hemlig never needs one.
    </p>
    <ul v-else-if="problems.length > 0" class="field-hint mt-1" role="alert">
      <li v-for="problem in problems" :key="problem">{{ problem }}</li>
    </ul>
  </div>
</template>
