<script setup lang="ts">
import { nextTick, onBeforeUnmount, ref } from "vue";
import { useTheme, type ThemePreference } from "../composables/useTheme";

const { preference } = useTheme();
const open = ref(false);
const trigger = ref<HTMLButtonElement>();
const menu = ref<HTMLDivElement>();

const options: { value: ThemePreference; label: string }[] = [
  { value: "system", label: "System" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

const items = (): HTMLButtonElement[] =>
  Array.from(menu.value?.querySelectorAll<HTMLButtonElement>("[role=menuitemradio]") ?? []);

const show = async (): Promise<void> => {
  open.value = true;
  await nextTick();
  const selected = items().find((item) => item.getAttribute("aria-checked") === "true");
  (selected ?? items()[0])?.focus();
  document.addEventListener("pointerdown", onOutside);
};

const hide = (returnFocus: boolean): void => {
  open.value = false;
  document.removeEventListener("pointerdown", onOutside);
  if (returnFocus) trigger.value?.focus();
};

const onOutside = (event: PointerEvent): void => {
  const target = event.target as Node;
  if (!menu.value?.contains(target) && !trigger.value?.contains(target)) hide(false);
};

const choose = (value: ThemePreference): void => {
  preference.value = value;
  hide(true);
};

const onKeydown = (event: KeyboardEvent): void => {
  const list = items();
  const index = list.indexOf(document.activeElement as HTMLButtonElement);
  const move = (next: number): void => {
    event.preventDefault();
    list[(next + list.length) % list.length]?.focus();
  };
  switch (event.key) {
    case "ArrowDown":
      return move(index + 1);
    case "ArrowUp":
      return move(index - 1);
    case "Home":
      return move(0);
    case "End":
      return move(list.length - 1);
    case "Escape":
      event.preventDefault();
      return hide(true);
    case "Tab":
      return hide(false);
  }
};

onBeforeUnmount(() => document.removeEventListener("pointerdown", onOutside));
</script>

<template>
  <div class="relative">
    <button
      ref="trigger"
      type="button"
      class="btn btn-ghost btn-icon"
      :class="open ? 'bg-surface-2 text-ink' : ''"
      aria-haspopup="menu"
      :aria-expanded="open"
      :aria-label="`Theme: ${preference}`"
      @click="open ? hide(false) : show()"
    >
      <!-- Half circle (system), sun (light), moon (dark). -->
      <svg v-if="preference === 'system'" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <circle cx="8" cy="8" r="6.25" fill="none" stroke="currentColor" stroke-width="1.5" />
        <path d="M8 1.75a6.25 6.25 0 0 1 0 12.5z" fill="currentColor" />
      </svg>
      <svg v-else-if="preference === 'light'" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <circle cx="8" cy="8" r="3" fill="currentColor" />
        <path
          d="M8 1v1.75M8 13.25V15M1 8h1.75M13.25 8H15M3.05 3.05l1.24 1.24M11.71 11.71l1.24 1.24M3.05 12.95l1.24-1.24M11.71 4.29l1.24-1.24"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
        />
      </svg>
      <svg v-else viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <path d="M13.5 9.6A5.75 5.75 0 0 1 6.4 2.5a5.75 5.75 0 1 0 7.1 7.1z" fill="currentColor" />
      </svg>
    </button>
    <div
      v-if="open"
      ref="menu"
      class="menu theme-menu absolute right-0 z-[60] mt-1.5"
      role="menu"
      aria-label="Theme"
      @keydown="onKeydown"
    >
      <p class="label-caps px-[9px] pt-1 pb-1.5" aria-hidden="true">Theme</p>
      <button
        v-for="option in options"
        :key="option.value"
        type="button"
        class="menu-item"
        role="menuitemradio"
        :aria-checked="preference === option.value"
        tabindex="-1"
        @click="choose(option.value)"
      >
        <span class="flex-1">{{ option.label }}</span>
        <svg
          v-if="preference === option.value"
          class="text-accent"
          viewBox="0 0 16 16"
          width="14"
          height="14"
          aria-hidden="true"
        >
          <path
            d="M3.5 8.5l3 3 6-7"
            fill="none"
            stroke="currentColor"
            stroke-width="1.75"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
    </div>
  </div>
</template>

<style scoped>
.theme-menu {
  animation: menu-in 0.1s ease-out;
}

@keyframes menu-in {
  from {
    opacity: 0;
    transform: translateY(-3px);
  }
}

@media (prefers-reduced-motion: reduce) {
  .theme-menu {
    animation: none;
  }
}
</style>
