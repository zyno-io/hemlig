// Applies the stored theme before first paint. A separate same-origin file
// because the console's Content-Security-Policy forbids inline scripts.
// Keep the storage key and logic in sync with src/composables/useTheme.ts.
(function () {
  var preference = "system";
  try {
    preference = localStorage.getItem("hemlig.theme") || "system";
  } catch (error) {
    // Storage can be unavailable (private mode, blocked site data).
  }
  var dark =
    preference === "dark" ||
    (preference !== "light" &&
      window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
})();
