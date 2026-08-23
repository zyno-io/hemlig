<script setup lang="ts">
import { computed } from "vue";
import { metadataPath, tagKey, tagValue } from "../api/payload";

export interface MetadataDraft {
  description: string;
  path: string;
  tags: { id: string; key: string; value: string }[];
}

const model = defineModel<MetadataDraft>({ required: true });

const pathError = computed(() =>
  model.value.path.length > 0 && !metadataPath.test(model.value.path)
    ? "Lowercase, slash-delimited segments only."
    : undefined,
);

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
      <span class="text-xs text-ink-muted">Folder</span>
      <input
        v-model="model.path"
        maxlength="256"
        placeholder="payments/stripe/production"
        class="mono mt-1 w-full rounded border border-line bg-surface px-2 py-1"
      />
      <span v-if="pathError" class="text-xs text-danger">{{ pathError }}</span>
      <span v-else class="text-xs text-ink-muted">
        Changing this moves the secret to a different folder in the tree.
      </span>
    </label>
    <slot name="after-path" />
    <label class="block">
      <span class="text-xs text-ink-muted">Description</span>
      <textarea
        v-model="model.description"
        maxlength="1024"
        rows="2"
        class="mt-1 w-full rounded border border-line bg-surface px-2 py-1"
      />
    </label>
    <div>
      <span class="text-xs text-ink-muted">Tags ({{ model.tags.length }} of 20)</span>
      <div v-for="tag in model.tags" :key="tag.id" class="mt-1 flex items-start gap-2">
        <input v-model="tag.key" placeholder="key" class="mono w-40 rounded border border-line bg-surface px-2 py-1" />
        <div class="flex-1">
          <input v-model="tag.value" placeholder="value" class="mono w-full rounded border border-line bg-surface px-2 py-1" />
          <span v-if="tagError(tag)" class="text-xs text-danger">{{ tagError(tag) }}</span>
        </div>
        <button
          type="button"
          class="rounded border border-line px-2 py-1 text-xs"
          @click="model.tags = model.tags.filter((t) => t.id !== tag.id)"
        >
          Remove
        </button>
      </div>
      <button
        v-if="model.tags.length < 20"
        type="button"
        class="mt-2 rounded border border-line px-2 py-1 text-xs"
        @click="addTag"
      >
        Add tag
      </button>
    </div>
    <p class="text-xs text-ink-muted">
      Paths and tags are organisational only. They never select a delivery target or
      grant access.
    </p>
  </div>
</template>
