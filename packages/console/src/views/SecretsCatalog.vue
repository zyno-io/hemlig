<script lang="ts">
import { tagKey, tagValue } from "../api/payload";

/**
 * Pure breadcrumb derivation, kept free of Vue so it is testable without
 * mounting the component. `path` mirrors the tree endpoint's `pathPrefix`: a
 * slash-joined string, `undefined` or empty at the root. A plain `<script>`
 * block shares module scope with the `<script setup>` block below, so this is
 * usable there directly, with no self-import.
 */
export interface PathCrumb {
  readonly segment: string;
  /** The prefix up to and including this segment; navigable on its own. */
  readonly path: string;
}

export const pathSegments = (path: string | undefined): PathCrumb[] => {
  if (path === undefined || path.length === 0) {
    return [];
  }
  const parts = path.split("/").filter((part) => part.length > 0);
  return parts.map((segment, index) => ({
    segment,
    path: parts.slice(0, index + 1).join("/"),
  }));
};

export interface CatalogTagFilter {
  readonly key: string;
  readonly value: string;
}

export interface ParsedCatalogFilter {
  /** Free-text tokens, joined with a single space; "" when there are none. */
  readonly text: string;
  readonly tags: readonly CatalogTagFilter[];
}

/**
 * Splits the smart-search input on whitespace and classifies each token: a
 * `key:value` token whose key and value both match `tagKey`/`tagValue` (the
 * same rules the service enforces on metadata.tags — see
 * src/domain/validation.ts) is a tag filter, everything else is free text.
 * A token that merely contains a colon but fails either pattern — a URL
 * fragment, say — is not an error: it falls back to free text. That is
 * unambiguous because a secret ID (`^[a-z][a-z0-9-]{2,63}$`) can never
 * contain a colon, so a bare word is never mistakable for a tag.
 */
export const parseCatalogFilter = (input: string): ParsedCatalogFilter => {
  const tags: CatalogTagFilter[] = [];
  const text: string[] = [];
  for (const token of input
    .trim()
    .split(/\s+/)
    .filter((part) => part.length > 0)) {
    const separator = token.indexOf(":");
    const key = separator === -1 ? undefined : token.slice(0, separator);
    const value = separator === -1 ? undefined : token.slice(separator + 1);
    if (
      key !== undefined &&
      value !== undefined &&
      tagKey.test(key) &&
      tagValue.test(value)
    ) {
      tags.push({ key, value });
    } else {
      text.push(token);
    }
  }
  return { text: text.join(" "), tags };
};
</script>

<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed, onUnmounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import { useCursorPages } from "../composables/useCursorPages";
import { ApiError } from "../api/errors";
import { isValidSecretIdentifier } from "../api/payload";
import type { CatalogEntry } from "../api/schemas";
import { useAppStore } from "../stores/app";

// `path` comes from the repeatable `:path*` route param on `secrets-browse`;
// it is `undefined` on the plain `secrets` (root) route. Either way this
// lives only in the URL — see the "Do not hold the current folder in a store
// only" requirement — so a location in the tree is shareable and survives a
// reload.
const props = defineProps<{ env: string; path?: string[] }>();
const store = useAppStore();
const route = useRoute();
const router = useRouter();

const currentPath = computed(() =>
  (props.path ?? []).filter((s) => s.length > 0).join("/"),
);
const breadcrumbs = computed(() => pathSegments(currentPath.value));

const crumbTo = (path: string) => ({
  name: "secrets-browse",
  params: { env: props.env, path: path.split("/") },
});

// Carries the folder currently being browsed into the create form as a query
// parameter, so a secret created from inside a folder defaults there instead
// of the root. A query param (not a route param) because it is optional
// prefill data, not part of the create route's identity, and it survives a
// reload since it lives in the URL.
const newSecretTo = computed(() => ({
  name: "secret-new",
  params: { env: props.env },
  query: currentPath.value.length > 0 ? { path: currentPath.value } : {},
}));

const treeQueryKey = computed(() => [
  "secrets-tree",
  props.env,
  currentPath.value,
]);

// One bounded, complete level of the tree. Reactive to env/path through the
// query key, the same pattern SecretDetail.vue uses for its secretId — no
// manual reload wiring needed for this half of the view.
const tree = useQuery({
  queryKey: treeQueryKey,
  queryFn: () =>
    store.requireApi().getSecretsTree({
      environment: props.env,
      pathPrefix: currentPath.value || undefined,
    }),
});

// --- Folder creation -------------------------------------------------------
//
// Folders are only ID prefixes. This dialog does not persist a record; it
// forwards the operator to the create form with that prefix prefilled.

const newFolderOpen = ref(false);
const newFolderSegment = ref("");

const newFolderPath = computed(() => {
  const trimmed = newFolderSegment.value.trim();
  if (trimmed.length === 0) {
    return "";
  }
  return currentPath.value.length > 0
    ? `${currentPath.value}/${trimmed}`
    : trimmed;
});

const newFolderPathError = computed(() => {
  if (
    newFolderSegment.value.trim().length === 0 ||
    isValidSecretIdentifier(newFolderPath.value)
  ) {
    return undefined;
  }
  return "Use lowercase ID segments (3–64 characters each), with no leading, trailing, or repeated slash.";
});

const canCreateFolder = computed(
  () =>
    newFolderSegment.value.trim().length > 0 &&
    newFolderPathError.value === undefined,
);

const closeNewFolder = (): void => {
  newFolderOpen.value = false;
  newFolderSegment.value = "";
};

const createFolder = async (): Promise<void> => {
  if (!canCreateFolder.value) {
    return;
  }
  const path = newFolderPath.value;
  await router.push({
    name: "secret-new",
    params: { env: props.env },
    query: { path },
  });
};

const secretFolderPath = (secretId: string): string | undefined => {
  const separator = secretId.lastIndexOf("/");
  return separator === -1 ? undefined : secretId.slice(0, separator);
};

// --- One smart search field -------------------------------------------
//
// A single field replaces what used to be two bordered sections (free text,
// tag filter). It is parsed into free text and tag terms token by token (see
// `parseCatalogFilter` above), and both compose into the same request — the
// backend accepts `q` and `tags` together — so there is no longer a reason
// to force applying one to clear the other.
const SEARCH_DEBOUNCE_MS = 300;
const catalogFilterFromRoute = (): string =>
  typeof route.query.catalogFilter === "string"
    ? route.query.catalogFilter
    : "";
const searchInput = ref(catalogFilterFromRoute());
const appliedInput = ref(catalogFilterFromRoute());
let searchDebounceHandle: ReturnType<typeof setTimeout> | undefined;

const cancelSearchDebounce = (): void => {
  if (searchDebounceHandle !== undefined) {
    clearTimeout(searchDebounceHandle);
    searchDebounceHandle = undefined;
  }
};

// Debouncing keeps a typed query to one request per pause in typing rather
// than one per keystroke, without delaying a cleared search.
watch(searchInput, (value) => {
  cancelSearchDebounce();
  const trimmed = value.trim();
  // Clearing the box issues no request, so there is nothing to debounce and
  // no reason to make the operator wait to get their folder tree back.
  if (trimmed.length === 0) {
    appliedInput.value = "";
    return;
  }
  searchDebounceHandle = setTimeout(() => {
    appliedInput.value = trimmed;
  }, SEARCH_DEBOUNCE_MS);
});

watch(
  () => route.query.catalogFilter,
  () => {
    const filter = catalogFilterFromRoute();
    if (filter !== appliedInput.value) {
      cancelSearchDebounce();
      searchInput.value = filter;
      appliedInput.value = filter;
    }
  },
);

onUnmounted(cancelSearchDebounce);

// Parsed live (not debounced): parsing is free and makes no request. Showing
// the interpretation only after the debounce would hide a
// typo'd tag falling back to free text for 300ms right when it matters.
const liveFilter = computed(() => parseCatalogFilter(searchInput.value));
// Parsed from the debounced value: this is what actually drives requests.
const appliedFilter = computed(() => parseCatalogFilter(appliedInput.value));
const hasFilter = computed(
  () =>
    appliedFilter.value.text.length > 0 || appliedFilter.value.tags.length > 0,
);
const tagsParam = computed(() =>
  appliedFilter.value.tags.map((tag) => `${tag.key}:${tag.value}`).join(","),
);

// A detail route cannot infer the catalog state it came from: a search is
// local UI state and a folder is represented by another route. Carry the
// small, safe return context explicitly so its back link restores either.
const secretTo = (secretId: string) => ({
  name: "secret",
  params: { env: props.env, secretId },
  query: {
    ...(currentPath.value.length === 0
      ? {}
      : { catalogPath: currentPath.value }),
    ...(appliedInput.value.length === 0
      ? {}
      : { catalogFilter: appliedInput.value }),
  },
});

// The tree route has no tag filter and no search box, so any filter switches
// the view into a flat result list instead of the folder tree. Which flat
// shape depends only on whether free text is present, because that is what
// the backend's own response shape depends on: tags alone is an ordinary
// cursor-paginated browse, but `q` (with or without tags) is a bounded
// complete-or-truncated search. This is a computed derived from parsing, not
// a piece of state the operator sets directly, so there is nothing to force
// clear when the two compose.
type CatalogView = "tree" | "tags" | "search";
const view = computed<CatalogView>(() => {
  if (!hasFilter.value) {
    return "tree";
  }
  return appliedFilter.value.text.length > 0 ? "search" : "tags";
});

const backToBrowsing = (): void => {
  cancelSearchDebounce();
  searchInput.value = "";
  appliedInput.value = "";
  flatPages.reset();
};

// --- Tags-only flat browsing, cursor-paginated ---------------------------
const flatPages = useCursorPages<CatalogEntry>(async (cursor) => {
  const page = await store.requireApi().listSecrets({
    environment: props.env,
    pathPrefix: currentPath.value || undefined,
    tags: tagsParam.value || undefined,
    cursor,
  });
  return { items: page.secrets, nextCursor: page.nextCursor };
});

watch([view, tagsParam, () => props.env, currentPath], () => {
  if (view.value === "tags") {
    flatPages.reset();
    void flatPages.loadMore();
  }
});

// --- Search, server-side, bounded, and environment-wide -------------------
//
// Deliberately ignoring `currentPath`, with or without tags composed in:
// "find this secret" is the job free text is for, and silently scoping to
// whatever folder happens to be open would hide the answer it exists to
// give. The template says so explicitly so this isn't a surprise in either
// direction.
const searchResults = useQuery({
  queryKey: computed(() => [
    "secrets-search",
    props.env,
    appliedFilter.value.text,
    tagsParam.value,
  ]),
  queryFn: () =>
    store.requireApi().listSecrets({
      environment: props.env,
      q: appliedFilter.value.text,
      tags: tagsParam.value || undefined,
    }),
  enabled: computed(() => view.value === "search"),
});

// A flat view — tag filter, search, or both together — is local UI state
// tied to the moment it was applied. If the environment or path moves out
// from under it (environment switch, browser back/forward, a pasted URL),
// re-scoping it silently would be more surprising than dropping back to
// browsing at the new location.
watch([() => props.env, currentPath], () => {
  if (hasFilter.value) {
    backToBrowsing();
  }
});

const refreshing = computed(() => {
  if (view.value === "tree") {
    return tree.isFetching.value;
  }
  return view.value === "tags"
    ? flatPages.loading.value
    : searchResults.isFetching.value;
});

const refresh = (): void => {
  if (view.value === "tree") {
    void tree.refetch();
  } else if (view.value === "tags") {
    flatPages.reset();
    void flatPages.loadMore();
  } else {
    void searchResults.refetch();
  }
};

// Duplicate tag keys and more than twenty tags are rejected by the service
// (see parseCatalogTagFilters in src/domain/validation.ts). That is a
// correctable typing mistake, not an application failure, so it is surfaced
// inline next to the field rather than through the generic ErrorNotice the
// results area otherwise shows.
const catalogError = computed<unknown>(() => {
  if (view.value === "tree") {
    return tree.error.value;
  }
  return view.value === "tags"
    ? flatPages.error.value
    : searchResults.error.value;
});
const tagRejection = computed(() =>
  catalogError.value instanceof ApiError &&
  catalogError.value.code === "bad_request"
    ? catalogError.value.message
    : undefined,
);
</script>

<template>
  <div class="space-y-4 text-sm">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-lg font-semibold">Secrets in {{ env }}</h1>
        <nav
          aria-label="Breadcrumb"
          class="mt-1 flex flex-wrap items-center gap-1 text-xs text-ink-muted"
        >
          <RouterLink
            class="hover:text-accent hover:underline"
            :to="{ name: 'secrets', params: { env } }"
            @click="backToBrowsing"
          >
            root
          </RouterLink>
          <template v-for="crumb in breadcrumbs" :key="crumb.path">
            <span aria-hidden="true">/</span>
            <RouterLink
              class="mono hover:text-accent hover:underline"
              :to="crumbTo(crumb.path)"
              @click="backToBrowsing"
            >
              {{ crumb.segment }}
            </RouterLink>
          </template>
        </nav>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <label class="sr-only" for="catalog-filter"
          >Search or filter secrets</label
        >
        <input
          id="catalog-filter"
          v-model="searchInput"
          class="mono w-72 rounded border border-line bg-surface px-2 py-1"
          type="search"
          placeholder="secret ID, or key:value"
        />
        <button
          class="rounded border border-line px-3 py-1"
          :disabled="refreshing"
          @click="refresh"
        >
          {{ refreshing ? "Loading…" : "Refresh" }}
        </button>
        <button
          class="rounded border border-line px-3 py-1"
          type="button"
          @click="newFolderOpen = !newFolderOpen"
        >
          New folder
        </button>
        <RouterLink
          class="rounded bg-accent px-3 py-1 text-white"
          :to="newSecretTo"
        >
          New secret
        </RouterLink>
      </div>
    </div>

    <div
      v-if="newFolderOpen"
      class="flex flex-wrap items-end gap-2 rounded border border-line bg-surface-raised p-3 text-xs"
    >
      <label class="flex flex-col gap-1">
        <span class="text-ink-muted"
          >New folder under {{ currentPath || "the root" }}</span
        >
        <input
          v-model="newFolderSegment"
          maxlength="256"
          class="mono w-56 rounded border border-line bg-surface px-2 py-1"
          placeholder="invoices"
        />
      </label>
      <span v-if="newFolderPathError" class="text-danger">{{
        newFolderPathError
      }}</span>
      <span v-else class="text-ink-muted">
        This only prefixes the next secret ID; empty folders are not stored.
      </span>
      <button
        class="rounded bg-accent px-3 py-1 text-white disabled:opacity-50"
        type="button"
        :disabled="!canCreateFolder"
        @click="createFolder"
      >
        Create secret here
      </button>
      <button
        class="rounded px-3 py-1 text-ink-muted"
        type="button"
        @click="closeNewFolder"
      >
        Cancel
      </button>
    </div>

    <div
      v-if="liveFilter.tags.length > 0 || liveFilter.text.length > 0"
      class="flex flex-wrap items-center gap-1.5 text-xs text-ink-muted"
    >
      <span>Understood as</span>
      <span
        v-for="tag in liveFilter.tags"
        :key="`${tag.key}:${tag.value}`"
        class="mono rounded bg-line/40 px-1.5 py-0.5 text-ink"
        >{{ tag.key }}={{ tag.value }}</span
      >
      <span v-if="liveFilter.text.length > 0"
        >matching "{{ liveFilter.text }}"</span
      >
    </div>

    <p
      v-if="tagRejection"
      class="rounded border border-warn/50 bg-warn/5 p-2 text-xs text-warn"
    >
      {{ tagRejection }}
    </p>

    <p
      v-if="view === 'tags'"
      class="rounded border border-accent/40 bg-accent/5 p-2 text-xs"
    >
      Showing a flat, tag-filtered result list under
      <span class="mono">{{ currentPath || "the root" }}</span> — not the folder
      tree.
      <button class="text-accent underline" @click="backToBrowsing">
        Back to browsing
      </button>
    </p>
    <p
      v-else-if="view === 'search'"
      class="rounded border border-accent/40 bg-accent/5 p-2 text-xs"
    >
      Showing search results across all of <span class="mono">{{ env }}</span> —
      every path, not just
      <span class="mono">{{ currentPath || "the root" }}</span
      >.
      <button class="text-accent underline" @click="backToBrowsing">
        Back to browsing
      </button>
    </p>

    <template v-if="view === 'tree'">
      <ErrorNotice v-if="tree.error.value" :error="tree.error.value" />
      <template v-else-if="tree.data.value">
        <!--
          The tree endpoint has no cursor: a level either fits in one bounded
          read or the server says so. Rendering a silently short list here
          would look complete when it is not.
        -->
        <p
          v-if="tree.data.value.truncated"
          class="rounded border border-warn/50 bg-warn/5 p-3 text-warn"
        >
          This level is incomplete — there are more folders or secrets here than
          the server returned in one page. Narrow with a tag filter or drill
          into a subfolder rather than trusting this list as the full contents.
        </p>

        <ul
          v-if="tree.data.value.folders.length > 0"
          class="divide-y divide-line/60 rounded border border-line"
        >
          <li
            v-for="folder in tree.data.value.folders"
            :key="folder.path"
            class="flex items-center justify-between px-3 py-2 hover:bg-surface-raised"
          >
            <RouterLink
              class="flex flex-1 items-center gap-2"
              :to="crumbTo(folder.path)"
            >
              <span aria-hidden="true">📁</span>
              <span class="mono">{{ folder.segment }}</span>
            </RouterLink>
            <span class="flex items-center gap-3 text-xs text-ink-muted">
              <span
                >{{ folder.secretCount }} secret{{
                  folder.secretCount === 1 ? "" : "s"
                }}</span
              >
            </span>
          </li>
        </ul>

        <table
          v-if="tree.data.value.secrets.length > 0"
          class="w-full border-collapse text-left"
        >
          <thead class="text-xs uppercase tracking-wide text-ink-muted">
            <tr class="border-b border-line">
              <th class="py-2 pr-3 font-medium">Secret ID</th>
              <th class="py-2 pr-3 font-medium">Tags</th>
              <th class="py-2 pr-3 font-medium">State</th>
              <th class="py-2 pr-3 font-medium">Entries</th>
              <th class="py-2 font-medium">Updated</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="secret in tree.data.value.secrets"
              :key="secret.secretId"
              class="border-b border-line/60"
            >
              <td class="py-2 pr-3">
                <RouterLink
                  class="mono text-accent hover:underline"
                  :to="secretTo(secret.secretId)"
                >
                  {{ secret.secretId }}
                </RouterLink>
              </td>
              <td class="py-2 pr-3 text-xs">
                <span
                  v-for="(value, key) in secret.metadata.tags ?? {}"
                  :key="key"
                  class="mr-1 inline-block rounded bg-line/40 px-1.5 py-0.5"
                  >{{ key }}:{{ value }}</span
                >
              </td>
              <td class="py-2 pr-3"><StateBadge :state="secret.state" /></td>
              <td class="py-2 pr-3 text-xs">
                {{ secret.payloadKeyCount ?? "—" }}
              </td>
              <td class="mono py-2 text-xs text-ink-muted">
                {{ secret.updatedAt ?? "—" }}
              </td>
            </tr>
          </tbody>
        </table>

        <p
          v-if="
            tree.data.value.folders.length === 0 &&
            tree.data.value.secrets.length === 0
          "
          class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
        >
          Nothing directly at this path.
        </p>
      </template>
      <p
        v-else
        class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
      >
        Loading…
      </p>
    </template>

    <template v-else-if="view === 'tags'">
      <ErrorNotice
        v-if="flatPages.error.value && !tagRejection"
        :error="flatPages.error.value"
      />

      <table
        v-if="flatPages.items.value.length > 0"
        class="w-full border-collapse text-left"
      >
        <thead class="text-xs uppercase tracking-wide text-ink-muted">
          <tr class="border-b border-line">
            <th class="py-2 pr-3 font-medium">Secret ID</th>
            <th class="py-2 pr-3 font-medium">Folder</th>
            <th class="py-2 pr-3 font-medium">Tags</th>
            <th class="py-2 pr-3 font-medium">State</th>
            <th class="py-2 pr-3 font-medium">Entries</th>
            <th class="py-2 font-medium">Updated</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="secret in flatPages.items.value"
            :key="secret.secretId"
            class="border-b border-line/60"
          >
            <td class="py-2 pr-3">
              <RouterLink
                class="text-accent hover:underline"
                :to="secretTo(secret.secretId)"
              >
                {{ secret.secretId }}
              </RouterLink>
            </td>
            <td class="mono py-2 pr-3 text-xs">
              {{ secretFolderPath(secret.secretId) ?? "Root" }}
            </td>
            <td class="py-2 pr-3 text-xs">
              <span
                v-for="(value, key) in secret.metadata.tags ?? {}"
                :key="key"
                class="mr-1 inline-block rounded bg-line/40 px-1.5 py-0.5"
                >{{ key }}:{{ value }}</span
              >
            </td>
            <td class="py-2 pr-3"><StateBadge :state="secret.state" /></td>
            <td class="py-2 pr-3 text-xs">
              {{ secret.payloadKeyCount ?? "—" }}
            </td>
            <td class="mono py-2 text-xs text-ink-muted">
              {{ secret.updatedAt ?? "—" }}
            </td>
          </tr>
        </tbody>
      </table>

      <!--
        A page is filtered after a bounded read, so an empty result with a
        cursor still outstanding does not mean there is nothing to find. "No
        secrets" is only truthful once the listing is exhausted.
      -->
      <p
        v-else-if="
          flatPages.exhausted.value &&
          !flatPages.loading.value &&
          !flatPages.error.value
        "
        class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
      >
        No secrets match under {{ currentPath || "the root" }} in {{ env }}.
      </p>
      <p
        v-else-if="!flatPages.error.value"
        class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
      >
        Searching…
      </p>

      <div
        v-if="
          !flatPages.exhausted.value &&
          flatPages.items.value.length > 0 &&
          !flatPages.error.value
        "
        class="flex items-center gap-3"
      >
        <button
          class="rounded border border-line px-3 py-1"
          :disabled="flatPages.loading.value"
          @click="flatPages.loadMore()"
        >
          {{ flatPages.loading.value ? "Loading…" : "Load more" }}
        </button>
        <span class="text-xs text-ink-muted"
          >{{ flatPages.pagesFetched.value }} pages read</span
        >
      </div>
      <p
        v-else-if="
          !flatPages.exhausted.value &&
          !flatPages.loading.value &&
          !flatPages.error.value
        "
        class="text-xs text-ink-muted"
      >
        More pages remain but none matched yet.
        <button class="text-accent underline" @click="flatPages.loadMore()">
          Keep searching
        </button>
      </p>
    </template>

    <template v-else>
      <ErrorNotice
        v-if="searchResults.error.value && !tagRejection"
        :error="searchResults.error.value"
      />
      <template v-else-if="searchResults.data.value">
        <!--
          A `q` response is bounded-complete, not paginated: there is no
          cursor to chase, so unlike the tag-filtered list above there is no
          ambiguity about whether "no matches" is final — this first (and
          only) response already is the answer. `truncated` here means the
          server's own search scan hit its bound, which is a different thing
          than a page running out; rendering the list silently in that case
          would look like the full answer when it might not be.
        -->
        <p
          v-if="searchResults.data.value.truncated"
          class="rounded border border-warn/50 bg-warn/5 p-3 text-warn"
        >
          This result set is incomplete — the search scanned as far as its bound
          allows and stopped. Narrow the query to see the full set of matches.
        </p>

        <table
          v-if="searchResults.data.value.secrets.length > 0"
          class="w-full border-collapse text-left"
        >
          <thead class="text-xs uppercase tracking-wide text-ink-muted">
            <tr class="border-b border-line">
              <th class="py-2 pr-3 font-medium">Secret ID</th>
              <th class="py-2 pr-3 font-medium">Folder</th>
              <th class="py-2 pr-3 font-medium">Tags</th>
              <th class="py-2 pr-3 font-medium">State</th>
              <th class="py-2 pr-3 font-medium">Entries</th>
              <th class="py-2 font-medium">Updated</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="secret in searchResults.data.value.secrets"
              :key="secret.secretId"
              class="border-b border-line/60"
            >
              <td class="py-2 pr-3">
                <RouterLink
                  class="text-accent hover:underline"
                  :to="secretTo(secret.secretId)"
                >
                  {{ secret.secretId }}
                </RouterLink>
              </td>
              <td class="mono py-2 pr-3 text-xs">
                {{ secretFolderPath(secret.secretId) ?? "Root" }}
              </td>
              <td class="py-2 pr-3 text-xs">
                <span
                  v-for="(value, key) in secret.metadata.tags ?? {}"
                  :key="key"
                  class="mr-1 inline-block rounded bg-line/40 px-1.5 py-0.5"
                  >{{ key }}:{{ value }}</span
                >
              </td>
              <td class="py-2 pr-3"><StateBadge :state="secret.state" /></td>
              <td class="py-2 pr-3 text-xs">
                {{ secret.payloadKeyCount ?? "—" }}
              </td>
              <td class="mono py-2 text-xs text-ink-muted">
                {{ secret.updatedAt ?? "—" }}
              </td>
            </tr>
          </tbody>
        </table>

        <p
          v-else
          class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
        >
          No matches for "{{ appliedFilter.text }}" in {{ env }}.
        </p>
      </template>
      <p
        v-else
        class="rounded border border-line bg-surface-raised p-6 text-center text-ink-muted"
      >
        Searching…
      </p>
    </template>
  </div>
</template>
