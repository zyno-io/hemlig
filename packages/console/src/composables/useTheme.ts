import { onScopeDispose, ref, watch } from "vue";

export type ThemePreference = "system" | "light" | "dark";

/** Shared with public/theme-init.js, which applies it before first paint. */
const storageKey = "hemlig.theme";

const readPreference = (): ThemePreference => {
  try {
    const stored = localStorage.getItem(storageKey);
    return stored === "light" || stored === "dark" ? stored : "system";
  } catch {
    return "system";
  }
};

const preference = ref<ThemePreference>(readPreference());

const systemQuery = (): MediaQueryList | undefined =>
  typeof window.matchMedia === "function"
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : undefined;

const apply = (): void => {
  const dark =
    preference.value === "dark" ||
    (preference.value === "system" && systemQuery()?.matches === true);
  document.documentElement.classList.toggle("dark", dark);
};

/**
 * The theme follows the operating system unless the administrator picks
 * Light or Dark; the choice is remembered per browser.
 */
export const useTheme = () => {
  const query = systemQuery();
  const onSystemChange = (): void => apply();
  query?.addEventListener("change", onSystemChange);
  onScopeDispose(() => query?.removeEventListener("change", onSystemChange));

  watch(
    preference,
    (value) => {
      try {
        if (value === "system") {
          localStorage.removeItem(storageKey);
        } else {
          localStorage.setItem(storageKey, value);
        }
      } catch {
        // Storage can be unavailable; the choice then lasts for this page.
      }
      apply();
    },
    { immediate: true },
  );

  return { preference };
};
