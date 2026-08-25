import { useQuery, useQueryClient, type UseQueryReturnType } from "@tanstack/vue-query";
import type { MaybeRefOrGetter } from "vue";
import type { EnvironmentListResponse } from "../api/schemas";
import { useAppStore } from "../stores/app";

/**
 * One query key, used by the root resolver, the shell's environment
 * switcher, and the `/environments` management view alike, so all three read
 * the same cache entry rather than each paying for its own read of a list.
 */
export const environmentsQueryKey = ["environments"] as const;

/**
 * The list requires an authenticated call. App.vue mounts all application
 * routes only after a session exists, so callers can use the default `true`.
 * The optional gate remains useful for focused embedding and tests.
 *
 * Global query defaults refresh metadata on focus, mount, and reconnect;
 * polling remains off — see main.ts.
 */
export const useEnvironmentsQuery = (
  enabled: MaybeRefOrGetter<boolean> = true,
): UseQueryReturnType<EnvironmentListResponse, unknown> => {
  const store = useAppStore();
  return useQuery({
    queryKey: environmentsQueryKey,
    queryFn: () => store.requireApi().listEnvironments(),
    enabled,
  });
};

/** Called after a successful create so the shared cache entry is refreshed. */
export const useInvalidateEnvironments = (): (() => Promise<void>) => {
  const queryClient = useQueryClient();
  return () => queryClient.invalidateQueries({ queryKey: environmentsQueryKey });
};
