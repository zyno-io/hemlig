import { ref, type Ref } from "vue";

export interface CursorPage<T> {
  readonly items: readonly T[];
  readonly nextCursor?: string;
}

export interface CursorPages<T> {
  readonly items: Ref<T[]>;
  readonly loading: Ref<boolean>;
  readonly exhausted: Ref<boolean>;
  readonly error: Ref<unknown>;
  /** Pages consumed so far, including ones the server filtered to nothing. */
  readonly pagesFetched: Ref<number>;
  reset(): void;
  loadMore(): Promise<void>;
}

/**
 * The catalog and consumer list queries read a bounded page and then apply
 * server-side filters, so a page can come back empty while still carrying a
 * cursor. Following one cursor per click would look broken, so each call
 * chases cursors until it has something to show or the listing is exhausted.
 *
 * The hop budget stops a filter that matches nothing from writing an unbounded
 * number of permanent audit objects in a single click.
 */
export const useCursorPages = <T>(
  fetchPage: (cursor: string | undefined) => Promise<CursorPage<T>>,
  hopBudget = 5,
): CursorPages<T> => {
  const items = ref<T[]>([]) as Ref<T[]>;
  const loading = ref(false);
  const exhausted = ref(false);
  const error = ref<unknown>(undefined);
  const pagesFetched = ref(0);
  let cursor: string | undefined;

  return {
    items,
    loading,
    exhausted,
    error,
    pagesFetched,
    reset() {
      items.value = [];
      cursor = undefined;
      exhausted.value = false;
      error.value = undefined;
      pagesFetched.value = 0;
    },
    async loadMore() {
      if (loading.value || exhausted.value) {
        return;
      }
      loading.value = true;
      error.value = undefined;
      try {
        for (let hop = 0; hop < hopBudget; hop += 1) {
          const page = await fetchPage(cursor);
          pagesFetched.value += 1;
          items.value = [...items.value, ...page.items];
          cursor = page.nextCursor;
          if (cursor === undefined) {
            exhausted.value = true;
            return;
          }
          if (page.items.length > 0) {
            return;
          }
        }
      } catch (caught) {
        error.value = caught;
      } finally {
        loading.value = false;
      }
    },
  };
};
