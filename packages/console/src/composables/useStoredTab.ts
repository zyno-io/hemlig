import { ref, type Ref } from "vue";

/** The last-chosen tab, remembered per viewer. Storage may be unavailable. */
export const useStoredTab = <T extends string>(
  key: string,
  options: readonly T[],
  fallback: T,
): [Ref<T>, (value: T) => void] => {
  let initial = fallback;
  try {
    const stored = window.localStorage.getItem(key);
    if (stored !== null && (options as readonly string[]).includes(stored)) {
      initial = stored as T;
    }
  } catch {
    // Per-viewer convenience only.
  }
  const tab = ref(initial) as Ref<T>;
  const select = (value: T): void => {
    tab.value = value;
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // Ignore.
    }
  };
  return [tab, select];
};
