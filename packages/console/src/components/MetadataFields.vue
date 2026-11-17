<script setup lang="ts">
import { tagKey, tagValue } from "../api/payload";

export interface MetadataDraft {
  description: string;
  tags: { id: string; key: string; value: string }[];
}

const model = defineModel<MetadataDraft>({ required: true });

const tagError = (tag: { key: string; value: string }): string | undefined => {
  if (tag.key.length === 0 && tag.value.length === 0) {
    return undefined;
  }
  if (!tagKey.test(tag.key)) {
    return "Key must be lowercase, start with a letter, 32 characters or fewer.";
  }
  if (!tagValue.test(tag.value)) {
    return "Value contains an unsupported character.";
  }
  return undefined;
};

const addTag = (): void => {
  model.value.tags.push({ id: crypto.randomUUID(), key: "", value: "" });
};
</script>

<template>
  <div class="space-y-3">
    <label class="block">
      <span class="field-label">Description</span>
      <textarea
        v-model="model.description"
        maxlength="1024"
        rows="2"
        class="input"
      />
    </label>
    <div>
      <span class="field-label">Tags ({{ model.tags.length }} of 20)</span>
      <div v-for="tag in model.tags" :key="tag.id" class="mt-2 flex items-start gap-2">
        <input v-model="tag.key" placeholder="key" class="input mono w-40" />
        <div class="flex-1">
          <input v-model="tag.value" placeholder="value" class="input mono" />
          <span v-if="tagError(tag)" class="field-error block">{{ tagError(tag) }}</span>
        </div>
        <button
          type="button"
          class="btn"
          @click="model.tags = model.tags.filter((t) => t.id !== tag.id)"
        >
          Remove
        </button>
      </div>
      <button
        v-if="model.tags.length < 20"
        type="button"
        class="btn mt-2"
        @click="addTag"
      >
        Add tag
      </button>
    </div>
    <p class="field-hint">
      Tags are organisational only. They never select a delivery target or
      grant access. Folders are derived from slash-separated secret IDs.
    </p>
  </div>
</template>
