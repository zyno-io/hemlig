<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, nextTick, reactive, ref, watch } from "vue";
import { useRouter } from "vue-router";
import BulkRevokeDialog from "../components/BulkRevokeDialog.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import GrantEvaluateTester from "../components/GrantEvaluateTester.vue";
import MutationState from "../components/MutationState.vue";
import RuleListField from "../components/RuleListField.vue";
import StateBadge from "../components/StateBadge.vue";
import { ApiError } from "../api/errors";
import { ED25519_WARNING, LEAF_KEY_ALGORITHMS } from "../api/pki-format";
import {
  draftFromGrant,
  draftProblems,
  draftSnapshot,
  draftToCreateRequest,
  draftToRequest,
  editableGrant,
  EKUS,
  emptyDraft,
  issuePathToField,
  KEY_USAGES,
  stableJson,
  SUBJECT_KEYS,
  type GrantDraft,
} from "../api/pki-grant-form";
import { fetchAllPages, PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import type {
  PkiGrantInput,
  PkiGrantPolicyStrict,
  PkiGrantValidationResult,
  PkiIssuanceGrant,
} from "../api/pki-schemas";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{
  env: string;
  consumerId: string;
  name?: string;
  caId?: string;
}>();

const store = useAppStore();
const router = useRouter();
const queryClient = useQueryClient();

const NAME_PATTERN = /^[a-z][a-z0-9-]{2,63}$/;

const isEdit = computed(() => props.name !== undefined);

// ------------------------------------------------------------- queries

const grantQuery = useQuery({
  ...PKI_QUERY_OPTIONS,
  queryKey: computed(() => pkiKeys.grant(props.consumerId, props.name ?? "")),
  queryFn: () => store.requireApi().getAdminIssuanceGrant(props.consumerId, props.name ?? ""),
  enabled: isEdit,
});

const casQuery = useQuery({
  ...PKI_QUERY_OPTIONS,
  queryKey: computed(() => pkiKeys.cas(props.env)),
  queryFn: () =>
    fetchAllPages(async (cursor) => {
      const page = await store
        .requireApi()
        .listPkiCas({ environment: props.env, cursor });
      return { items: page.cas, nextCursor: page.nextCursor };
    }),
});

// ----------------------------------------------------------- draft state

const draft = reactive<GrantDraft>(emptyDraft());
const savedGrant = ref<PkiIssuanceGrant | undefined>();
const strictPolicy = ref<PkiGrantPolicyStrict | undefined>();
const baseline = ref(draftSnapshot(draft));
const staleNote = ref<string | undefined>();

const caDetail = useQuery({
  ...PKI_QUERY_OPTIONS,
  queryKey: computed(() => pkiKeys.ca(draft.caId)),
  queryFn: () => store.requireApi().getPkiCa(draft.caId),
  enabled: computed(() => draft.caId !== ""),
});

const setDraft = (next: GrantDraft): void => {
  Object.assign(draft, next);
  draft.origin = next.origin;
  draft.originExpiresAt = next.originExpiresAt;
};

const adoptGrant = (grant: PkiIssuanceGrant): void => {
  savedGrant.value = grant;
  const policy = editableGrant(grant);
  strictPolicy.value = policy;
  if (policy !== undefined) {
    setDraft(draftFromGrant(grant, policy));
    baseline.value = draftSnapshot(draft);
  }
};

watch(
  () => grantQuery.data.value,
  (grant) => {
    // Adopt once. A background refetch must never overwrite an edited draft.
    if (grant !== undefined && savedGrant.value === undefined) {
      adoptGrant(grant);
    }
  },
  { immediate: true },
);

if (!isEdit.value && props.caId !== undefined) {
  draft.caId = props.caId;
  baseline.value = draftSnapshot(draft);
}

const issuingCas = computed(() =>
  (casQuery.data.value ?? []).filter((ca) => ca.kind !== "ROOT" && ca.status === "ACTIVE"),
);
const caOptions = computed(() => {
  const options = issuingCas.value.map((ca) => ({
    caId: ca.caId,
    label: ca.displayName ?? ca.name,
  }));
  if (draft.caId !== "" && !options.some((option) => option.caId === draft.caId)) {
    options.push({ caId: draft.caId, label: `${draft.caId} (not an active issuing CA)` });
  }
  return options;
});

// With exactly one issuing CA there is nothing to choose.
watch(issuingCas, (cas) => {
  if (!isEdit.value && draft.caId === "" && cas.length === 1 && cas[0] !== undefined) {
    draft.caId = cas[0].caId;
  }
});

// A new grant starts with lifetimes that fit the chosen CA.
let autoLifetime = emptyDraft().lifetimeDefault;
let autoMin = emptyDraft().lifetimeMin;
watch(
  () => caDetail.data.value,
  (ca) => {
    if (ca === undefined || isEdit.value) {
      return;
    }
    const fitted = emptyDraft(ca);
    if (draft.lifetimeDefault === autoLifetime && draft.lifetimeMax === autoLifetime) {
      draft.lifetimeDefault = fitted.lifetimeDefault;
      draft.lifetimeMax = fitted.lifetimeMax;
      if (draft.lifetimeMin === autoMin) {
        draft.lifetimeMin = fitted.lifetimeMin;
      }
      baseline.value = draftSnapshot(draft);
    }
    autoLifetime = fitted.lifetimeDefault;
    autoMin = fitted.lifetimeMin;
  },
);

const dirty = computed(() => draftSnapshot(draft) !== baseline.value);

const readOnly = computed(
  () =>
    isEdit.value &&
    savedGrant.value !== undefined &&
    (strictPolicy.value === undefined || savedGrant.value.status === "DELETED"),
);
const unsupportedPolicy = computed(
  () => isEdit.value && savedGrant.value !== undefined && strictPolicy.value === undefined,
);

const version = computed(() => savedGrant.value?.version);

// ---------------------------------------------------- field-level issues

interface FieldError {
  readonly field: string;
  readonly line?: number;
  readonly message: string;
  readonly path?: string;
}

const validation = ref<PkiGrantValidationResult | undefined>();
const validating = ref(false);
const validateFailure = ref<unknown>();
const localProblems = ref<string[]>([]);

watch(
  () => draftSnapshot(draft),
  () => {
    validation.value = undefined;
    localProblems.value = [];
  },
);

const failure = computed(() => {
  const phase = saveMutation.phase.value;
  return phase.kind === "failed" ? phase.error : undefined;
});

const issues = computed<FieldError[]>(() => {
  const out: FieldError[] = [];
  for (const issue of validation.value?.errors ?? []) {
    const target = issuePathToField(issue.path);
    out.push({
      field: target.field,
      ...(target.line === undefined ? {} : { line: target.line }),
      message: issue.message,
      path: issue.path,
    });
  }
  const error = failure.value;
  if (error instanceof ApiError) {
    if (error.reason === "grant_exists") {
      out.push({ field: "name", message: "A grant with that name already exists." });
    } else if (error.reason === "invalid_grant_policy") {
      const path = error.details?.path;
      if (typeof path === "string") {
        const target = issuePathToField(path);
        out.push({
          field: target.field,
          ...(target.line === undefined ? {} : { line: target.line }),
          message: error.message,
          path,
        });
      }
    }
  }
  return out;
});

const lineErrors = (field: string): Record<number, string> => {
  const out: Record<number, string> = {};
  for (const issue of issues.value) {
    if (issue.field === field && issue.line !== undefined) {
      out[issue.line] = issue.message;
    }
  }
  return out;
};

const fieldMessage = (field: string): string | undefined =>
  issues.value.find((issue) => issue.field === field && issue.line === undefined)?.message;

const nameProblem = computed(() =>
  !isEdit.value && draft.name !== "" && !NAME_PATTERN.test(draft.name)
    ? "Use 3 to 64 lowercase letters, digits and hyphens, starting with a letter."
    : undefined,
);

const warnings = computed(() => [
  ...(validation.value?.warnings ?? []),
  ...(savedGrant.value?.warnings ?? []).filter(() => validation.value === undefined),
]);

// ---------------------------------------------------------- CA guidance

const caAlgorithms = computed<readonly string[] | undefined>(
  () => caDetail.data.value?.policy.leafKeyAlgorithms,
);
const algorithmDisabled = (algorithm: string): boolean =>
  caAlgorithms.value !== undefined &&
  !caAlgorithms.value.includes(algorithm) &&
  !draft.keyAlgorithms.includes(algorithm as (typeof draft.keyAlgorithms)[number]);

const quotaWarning = computed(() => {
  const perHour = Number(draft.quotaPerHour);
  const limit = caDetail.data.value?.policy.issuancePerHour;
  return limit !== undefined && Number.isFinite(perHour) && perHour > limit
    ? `Per-hour quota ${perHour} is above the CA's issuance rate of ${limit} per hour; the CA limit still applies.`
    : undefined;
});

const testerAlgorithms = computed<readonly string[]>(() => {
  const stored = savedGrant.value === undefined ? undefined : strictPolicy.value?.keyAlgorithms;
  return stored ?? caAlgorithms.value ?? LEAF_KEY_ALGORITHMS;
});

// ----------------------------------------------------------- mutations

interface SaveInput {
  readonly body: PkiGrantInput & { name?: string };
  readonly version?: string;
}

const saveMutation = useGuardedMutation<SaveInput, PkiIssuanceGrant>({
  family: "pki",
  mutate: (input, key) => {
    const api = store.requireApi();
    if (input.version === undefined) {
      return api.createIssuanceGrant(
        props.consumerId,
        input.body as PkiGrantInput & { name: string },
        key,
      );
    }
    return api.updateIssuanceGrant(
      props.consumerId,
      props.name ?? "",
      input.version,
      input.body,
      key,
    );
  },
});

const deleteMutation = useGuardedMutation<string, PkiIssuanceGrant>({
  family: "pki",
  mutate: (grantVersion, key) =>
    store
      .requireApi()
      .deleteIssuanceGrant(props.consumerId, props.name ?? "", grantVersion, key),
});

const tester = ref<InstanceType<typeof GrantEvaluateTester> | undefined>();

const invalidateGrantLists = async (): Promise<void> => {
  await queryClient.invalidateQueries({ queryKey: ["pki", "consumer-grants", props.consumerId] });
  if (draft.caId !== "") {
    await queryClient.invalidateQueries({ queryKey: pkiKeys.caGrants(draft.caId) });
  }
};

const checkLocally = (): boolean => {
  const problems = draftProblems(draft);
  if (nameProblem.value !== undefined) {
    problems.push(nameProblem.value);
  }
  if (!isEdit.value && draft.name.trim() === "") {
    problems.push("A name is required.");
  }
  localProblems.value = problems;
  return problems.length === 0;
};

const validate = async (): Promise<void> => {
  if (validating.value || readOnly.value || !checkLocally()) {
    return;
  }
  validating.value = true;
  validateFailure.value = undefined;
  try {
    const api = store.requireApi();
    validation.value =
      isEdit.value && version.value !== undefined
        ? await api.validateIssuanceGrantUpdate(
            props.consumerId,
            props.name ?? "",
            version.value,
            draftToRequest(draft),
          )
        : await api.validateIssuanceGrantCreate(props.consumerId, draftToCreateRequest(draft));
  } catch (caught) {
    validateFailure.value = caught;
    validation.value = undefined;
  } finally {
    validating.value = false;
  }
};

const saving = computed(() => saveMutation.phase.value.kind === "submitting");

const save = async (): Promise<void> => {
  if (saving.value || readOnly.value || !checkLocally()) {
    return;
  }
  const editing = isEdit.value;
  if (editing && version.value === undefined) {
    return;
  }
  // What was sent. Edits made while the outcome is unknown stay dirty, also on a later retry.
  submittedSnapshot = draftSnapshot(draft);
  await applySaved(
    await saveMutation.submit(
      editing
        ? { body: draftToRequest(draft), version: version.value }
        : { body: draftToCreateRequest(draft) },
    ),
    editing,
    submittedSnapshot,
  );
};

let submittedSnapshot: string | undefined;

// A retry replays the same key, so its success must be handled exactly like a
// first-time success (adopting the returned version).
const retrySave = async (): Promise<void> => {
  await applySaved(await saveMutation.retry(), isEdit.value, submittedSnapshot);
};

const applySaved = async (
  result: PkiIssuanceGrant | undefined,
  editing: boolean,
  sent: string | undefined,
): Promise<void> => {
  if (result === undefined) {
    return;
  }
  staleNote.value = undefined;
  savedGrant.value = result;
  baseline.value = sent ?? draftSnapshot(draft);
  // The response is the fresh grant; storing it avoids another audited read.
  queryClient.setQueryData(pkiKeys.grant(props.consumerId, result.name), result);
  await invalidateGrantLists();
  if (!editing) {
    strictPolicy.value = editableGrant(result);
    saveMutation.reset();
    await router.replace({
      name: "consumer-pki-grant",
      params: { env: props.env, consumerId: props.consumerId, name: result.name },
    });
    return;
  }
  // Show the effect of the change on the last test, once.
  await nextTick();
  await tester.value?.rerun();
};

const reloadStale = async (): Promise<void> => {
  if (!isEdit.value) {
    // Create mode has no grant to refetch (the query is disabled).
    saveMutation.reset();
    return;
  }
  const fresh = (await grantQuery.refetch()).data;
  if (fresh === undefined) {
    return;
  }
  // Rebase the operator's edits onto the fresh grant, field by field, so
  // another operator's saved change is never overwritten by the old draft.
  const oldSaved = savedGrant.value;
  const oldPolicy = strictPolicy.value;
  const policy = editableGrant(fresh);
  const conflicts: string[] = [];
  if (oldSaved !== undefined && oldPolicy !== undefined && policy !== undefined) {
    const base = draftFromGrant(oldSaved, oldPolicy) as unknown as Record<string, unknown>;
    const freshDraft = draftFromGrant(fresh, policy);
    const merged = freshDraft as unknown as Record<string, unknown>;
    const current = draft as unknown as Record<string, unknown>;
    for (const field of Object.keys(base)) {
      if (field === "origin" || field === "originExpiresAt") {
        continue;
      }
      if (stableJson(current[field]) === stableJson(base[field])) {
        continue;
      }
      if (stableJson(merged[field]) === stableJson(base[field])) {
        merged[field] = current[field];
      } else {
        conflicts.push(field);
      }
    }
    setDraft(freshDraft);
    savedGrant.value = fresh;
    strictPolicy.value = policy;
    baseline.value = draftSnapshot(draftFromGrant(fresh, policy));
  } else {
    savedGrant.value = fresh;
    strictPolicy.value = policy;
    if (policy !== undefined) {
      baseline.value = draftSnapshot(draftFromGrant(fresh, policy));
    }
  }
  staleNote.value =
    `${fresh.updatedBy.email ?? fresh.updatedBy.id} saved version ${fresh.version} at ${fresh.updatedAt}; review and save again.` +
    (conflicts.length > 0
      ? ` Your edits to ${conflicts.join(", ")} were replaced by the newer saved values; reapply them if still needed.`
      : "");
  saveMutation.reset();
};

const reloadDelete = async (): Promise<void> => {
  const fresh = (await grantQuery.refetch()).data;
  if (fresh !== undefined) {
    savedGrant.value = fresh;
  }
  deleteMutation.reset();
};

const discardDraft = async (): Promise<void> => {
  const fresh = (await grantQuery.refetch()).data;
  if (fresh !== undefined) {
    adoptGrant(fresh);
  }
  staleNote.value = undefined;
  saveMutation.reset();
};

// -------------------------------------------------------------- delete

const confirmingDelete = ref(false);
const deletedGrant = ref<PkiIssuanceGrant | undefined>();
const revokingAfterDelete = ref(false);

const deleting = computed(() => deleteMutation.phase.value.kind === "submitting");

const confirmDelete = async (): Promise<void> => {
  if (deleting.value || version.value === undefined) {
    return;
  }
  confirmingDelete.value = false;
  await applyDeleted(await deleteMutation.submit(version.value));
};

const retryDelete = async (): Promise<void> => {
  await applyDeleted(await deleteMutation.retry());
};

const applyDeleted = async (result: PkiIssuanceGrant | undefined): Promise<void> => {
  if (result !== undefined) {
    deletedGrant.value = result;
    await queryClient.invalidateQueries({ queryKey: ["pki", "consumer-grants", props.consumerId] });
    await queryClient.invalidateQueries({ queryKey: ["pki", "ca-grants"] });
  }
};

const toggle = <T extends string>(values: T[], value: T): void => {
  const index = values.indexOf(value);
  if (index === -1) {
    values.push(value);
  } else {
    values.splice(index, 1);
  }
};
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <RouterLink
          class="link text-xs"
          :to="{
            name: 'consumer',
            params: { env, consumerId },
            query: { tab: 'certificate-grants' },
          }"
        >
          ← {{ consumerId }}
        </RouterLink>
        <h1 class="page-title">
          <template v-if="isEdit"><span class="mono">{{ name }}</span></template>
          <template v-else>New issuance grant</template>
        </h1>
      </div>
      <div class="page-actions">
        <StateBadge v-if="savedGrant" :state="savedGrant.status" />
        <button
          v-if="isEdit && savedGrant && savedGrant.status !== 'DELETED' && !deletedGrant"
          class="btn btn-danger"
          data-testid="grant-delete-open"
          @click="confirmingDelete = true"
        >
          Delete
        </button>
      </div>
    </div>

    <div class="space-y-4">
      <ErrorNotice v-if="grantQuery.error.value" :error="grantQuery.error.value" />

      <section v-if="deletedGrant" class="notice notice-success" role="status" data-testid="deleted-panel">
        <p class="notice-title">Grant deleted.</p>
        <p class="mt-1">
          Deleting a grant does not revoke certificates it already issued. They stay valid
          until they expire or you revoke them.
        </p>
        <div class="mt-3 flex gap-2">
          <button class="btn btn-danger" data-testid="revoke-after-delete" @click="revokingAfterDelete = true">
            Revoke its certificates…
          </button>
          <RouterLink
            class="btn"
            :to="{ name: 'consumer', params: { env, consumerId }, query: { tab: 'certificate-grants' } }"
          >Back to consumer</RouterLink>
        </div>
      </section>

      <template v-else>
        <MutationState
          :phase="deleteMutation.phase.value"
          :can-retry="deleteMutation.canRetry.value"
          family="pki"
          intent="delete this grant"
          @retry="retryDelete"
          @reload="reloadDelete"
        />

        <div
          v-if="unsupportedPolicy && savedGrant"
          class="notice notice-warning"
          role="status"
          data-testid="readonly-notice"
        >
          <p class="notice-title">Read-only</p>
          <p class="mt-1">
            This grant uses fields this console does not edit; use the CLI. Saving from a form
            that cannot represent them would erase them.
          </p>
          <pre class="code-block mono mt-2 max-h-72 overflow-auto text-xs">{{ JSON.stringify(savedGrant.policy, null, 2) }}</pre>
        </div>

        <form v-else class="space-y-4" @submit.prevent="save">
          <fieldset :disabled="readOnly || saving" class="space-y-4">
            <section class="card card-body space-y-3">
              <h2 class="section-title">Grant</h2>
              <label v-if="!isEdit" class="block">
                <span class="field-label">Name</span>
                <input v-model="draft.name" class="input mono" autocomplete="off" data-testid="grant-name" />
                <p v-if="nameProblem" class="field-error">{{ nameProblem }}</p>
                <p v-if="fieldMessage('name')" class="field-error" role="alert">{{ fieldMessage('name') }}</p>
              </label>
              <label class="block">
                <span class="field-label">CA</span>
                <select v-model="draft.caId" class="input mono" data-testid="grant-ca">
                  <option value="" disabled>Choose an issuing CA</option>
                  <option v-for="option in caOptions" :key="option.caId" :value="option.caId">
                    {{ option.label }} ({{ option.caId }})
                  </option>
                </select>
                <p v-if="isEdit" class="field-hint">
                  Changing the CA migrates this grant: new certificates come from the new CA.
                  Existing certificates are unaffected.
                </p>
                <p v-if="fieldMessage('caId')" class="field-error" role="alert">{{ fieldMessage('caId') }}</p>
              </label>
              <div class="grid gap-3 sm:grid-cols-3">
                <label class="block sm:col-span-2">
                  <span class="field-label">Display name</span>
                  <input v-model="draft.displayName" class="input" maxlength="128" data-testid="grant-display-name" />
                  <p class="field-hint">Clearing this removes the display name.</p>
                </label>
                <label class="block">
                  <span class="field-label">Status</span>
                  <select v-model="draft.status" class="input" data-testid="grant-status">
                    <option value="ACTIVE">ACTIVE</option>
                    <option value="DISABLED">DISABLED</option>
                  </select>
                </label>
              </div>
              <label class="block">
                <span class="field-label">Expires (optional)</span>
                <input v-model="draft.expiresAt" type="datetime-local" class="input" />
                <p v-if="fieldMessage('expiresAt')" class="field-error">{{ fieldMessage('expiresAt') }}</p>
              </label>
            </section>

            <section class="card card-body space-y-3">
              <h2 class="section-title">Names</h2>
              <p class="field-hint mt-0">
                Deny by default: an empty allow list permits nothing. DNS rules are exact names,
                <span class="mono">*.</span> (one label) or <span class="mono">**.</span> (any depth).
              </p>
              <div class="grid gap-3 sm:grid-cols-2">
                <RuleListField v-model="draft.dnsAllow" label="DNS allow" :errors="lineErrors('dnsAllow')" />
                <RuleListField v-model="draft.dnsDeny" label="DNS deny" :errors="lineErrors('dnsDeny')" />
                <RuleListField v-model="draft.ipAllow" label="IP allow (CIDR)" :errors="lineErrors('ipAllow')" />
                <RuleListField v-model="draft.ipDeny" label="IP deny (CIDR)" :errors="lineErrors('ipDeny')" />
                <RuleListField v-model="draft.uriAllow" label="URI allow" :errors="lineErrors('uriAllow')" />
                <RuleListField v-model="draft.uriDeny" label="URI deny" :errors="lineErrors('uriDeny')" />
              </div>
              <label class="flex items-center gap-2 text-[13px]">
                <input v-model="draft.allowWildcardNames" type="checkbox" />
                Allow wildcard names
              </label>
              <div class="grid gap-3 sm:grid-cols-3">
                <label class="block">
                  <span class="field-label">Common name</span>
                  <select v-model="draft.cnMode" class="input">
                    <option value="">Server default</option>
                    <option value="san">Must equal an allowed SAN</option>
                    <option value="forbid">Forbidden</option>
                  </select>
                </label>
                <label class="flex items-end gap-2 pb-2 text-[13px]">
                  <input v-model="draft.addToSans" type="checkbox" />
                  Add common name to SANs
                </label>
                <label class="block">
                  <span class="field-label">Maximum SANs</span>
                  <input v-model="draft.maxSans" class="input" inputmode="numeric" placeholder="1 to 100" />
                  <p v-if="fieldMessage('maxSans')" class="field-error">{{ fieldMessage('maxSans') }}</p>
                </label>
              </div>
            </section>

            <section class="card card-body space-y-3">
              <h2 class="section-title">Subject</h2>
              <p class="field-hint mt-0">Glob patterns the requested subject attributes must match.</p>
              <div class="grid gap-3 sm:grid-cols-2">
                <RuleListField
                  v-for="key in SUBJECT_KEYS"
                  :key="key"
                  v-model="draft.subjectAllow[key]"
                  :label="`Allow ${key}`"
                  :errors="lineErrors(`subjectAllow.${key}`)"
                />
              </div>
            </section>

            <section class="card card-body space-y-3">
              <h2 class="section-title">Keys and usages</h2>
              <fieldset>
                <legend class="field-label">Key algorithms</legend>
                <label
                  v-for="algorithm in LEAF_KEY_ALGORITHMS"
                  :key="algorithm"
                  class="mr-3 inline-flex items-center gap-1 text-xs"
                >
                  <input
                    v-model="draft.keyAlgorithms"
                    type="checkbox"
                    :value="algorithm"
                    :disabled="algorithmDisabled(algorithm)"
                  />
                  {{ algorithm }}
                </label>
                <p class="field-hint">
                  None selected uses the server default. Algorithms the CA does not allow are
                  disabled<template v-if="caAlgorithms"> (this CA allows {{ caAlgorithms.join(", ") }})</template>.
                </p>
                <p v-if="draft.keyAlgorithms.includes('ED25519')" class="notice notice-warning mt-2" data-testid="ed25519-warning">
                  {{ ED25519_WARNING }}
                </p>
              </fieldset>
              <div class="grid gap-3 sm:grid-cols-3">
                <fieldset>
                  <legend class="field-label">Key usages</legend>
                  <label v-for="usage in KEY_USAGES" :key="usage" class="mr-3 inline-flex items-center gap-1 text-xs">
                    <input type="checkbox" :checked="draft.keyUsages.includes(usage)" @change="toggle(draft.keyUsages, usage)" />
                    {{ usage }}
                  </label>
                </fieldset>
                <fieldset>
                  <legend class="field-label">EKU allowed</legend>
                  <label v-for="usage in EKUS" :key="usage" class="mr-3 inline-flex items-center gap-1 text-xs">
                    <input type="checkbox" :checked="draft.ekuAllow.includes(usage)" @change="toggle(draft.ekuAllow, usage)" />
                    {{ usage }}
                  </label>
                </fieldset>
                <fieldset>
                  <legend class="field-label">EKU default</legend>
                  <label v-for="usage in EKUS" :key="usage" class="mr-3 inline-flex items-center gap-1 text-xs">
                    <input type="checkbox" :checked="draft.ekuDefault.includes(usage)" @change="toggle(draft.ekuDefault, usage)" />
                    {{ usage }}
                  </label>
                </fieldset>
              </div>
            </section>

            <section class="card card-body space-y-3">
              <h2 class="section-title">Lifetimes</h2>
              <p class="field-hint mt-0">
                Use 3600s, 90m, 24h or 90d.
                <template v-if="caDetail.data.value">
                  This CA allows at most {{ caDetail.data.value.policy.maxLeafLifetimeSeconds }}s.
                </template>
              </p>
              <div class="grid gap-3 sm:grid-cols-3">
                <label class="block">
                  <span class="field-label">Default</span>
                  <input v-model="draft.lifetimeDefault" class="input mono" data-testid="lifetime-default" />
                  <p v-if="fieldMessage('lifetimeDefault')" class="field-error">{{ fieldMessage('lifetimeDefault') }}</p>
                </label>
                <label class="block">
                  <span class="field-label">Maximum</span>
                  <input v-model="draft.lifetimeMax" class="input mono" data-testid="lifetime-max" />
                  <p v-if="fieldMessage('lifetimeMax')" class="field-error">{{ fieldMessage('lifetimeMax') }}</p>
                </label>
                <label class="block">
                  <span class="field-label">Minimum</span>
                  <input v-model="draft.lifetimeMin" class="input mono" />
                  <p v-if="fieldMessage('lifetimeMin')" class="field-error">{{ fieldMessage('lifetimeMin') }}</p>
                </label>
              </div>
            </section>

            <section class="card card-body space-y-3">
              <h2 class="section-title">Forced values</h2>
              <p class="notice notice-warning" data-testid="forced-warning">
                Forced values are added to every certificate and bypass the name allowlists above.
                The CA's constraints and the reserved names still apply.
              </p>
              <div class="grid gap-3 sm:grid-cols-2">
                <label v-for="key in SUBJECT_KEYS" :key="key" class="block">
                  <span class="field-label">Subject {{ key }}</span>
                  <input v-model="draft.forcedSubject[key]" class="input" />
                  <p v-if="fieldMessage(`forcedSubject.${key}`)" class="field-error">{{ fieldMessage(`forcedSubject.${key}`) }}</p>
                </label>
              </div>
              <div class="grid gap-3 sm:grid-cols-3">
                <RuleListField v-model="draft.forcedDns" label="Forced DNS SANs" :errors="lineErrors('forcedDns')" />
                <RuleListField v-model="draft.forcedIp" label="Forced IP SANs" :errors="lineErrors('forcedIp')" />
                <RuleListField v-model="draft.forcedUri" label="Forced URI SANs" :errors="lineErrors('forcedUri')" />
              </div>
              <RuleListField
                v-model="draft.forcedPolicies"
                label="Certificate policy OIDs"
                :errors="lineErrors('forcedPolicies')"
              />
            </section>

            <section class="card card-body space-y-3">
              <h2 class="section-title">Quotas</h2>
              <div class="grid gap-3 sm:grid-cols-2">
                <label class="block">
                  <span class="field-label">Per hour</span>
                  <input v-model="draft.quotaPerHour" class="input" inputmode="numeric" placeholder="default 100" />
                  <p v-if="fieldMessage('quotaPerHour')" class="field-error">{{ fieldMessage('quotaPerHour') }}</p>
                </label>
                <label class="block">
                  <span class="field-label">Per day</span>
                  <input v-model="draft.quotaPerDay" class="input" inputmode="numeric" placeholder="default 1000" />
                  <p v-if="fieldMessage('quotaPerDay')" class="field-error">{{ fieldMessage('quotaPerDay') }}</p>
                </label>
              </div>
              <p v-if="quotaWarning" class="notice notice-warning" data-testid="quota-warning">{{ quotaWarning }}</p>
            </section>
          </fieldset>

          <div v-if="localProblems.length > 0" class="notice notice-danger" role="alert" data-testid="local-problems">
            <ul>
              <li v-for="problem in localProblems" :key="problem">{{ problem }}</li>
            </ul>
          </div>

          <div v-if="validation" class="notice" :class="validation.valid ? 'notice-success' : 'notice-danger'" role="status" data-testid="validation-result">
            <p class="notice-title">{{ validation.valid ? "The grant is valid." : "The grant has errors." }}</p>
            <ul class="mt-1">
              <li v-for="issue in validation.errors" :key="`e:${issue.path}:${issue.message}`">
                <span class="mono text-xs">{{ issue.path }}</span>: {{ issue.message }}
              </li>
            </ul>
          </div>
          <div v-if="warnings.length > 0" class="notice notice-warning" role="status">
            <p class="notice-title">Warnings</p>
            <ul class="mt-1">
              <li v-for="issue in warnings" :key="`w:${issue.path}:${issue.message}`">
                <span class="mono text-xs">{{ issue.path }}</span>: {{ issue.message }}
              </li>
            </ul>
          </div>
          <ErrorNotice v-if="validateFailure" :error="validateFailure" context="Validation failed." />

          <p v-if="staleNote" class="notice notice-warning" role="status" data-testid="stale-note">{{ staleNote }}</p>

          <MutationState
            :phase="saveMutation.phase.value"
            :can-retry="saveMutation.canRetry.value"
            family="pki"
            intent="save this grant"
            @retry="retrySave"
            @reload="reloadStale"
          />
          <button
            v-if="saveMutation.phase.value.kind === 'stale'"
            type="button"
            class="btn"
            data-testid="discard-draft"
            @click="discardDraft"
          >
            Discard my draft
          </button>

          <div v-if="!readOnly" class="flex gap-2">
            <button type="button" class="btn" :disabled="validating || saving" data-testid="grant-validate" @click="validate">
              {{ validating ? "Validating…" : "Validate" }}
            </button>
            <button type="submit" class="btn btn-primary" :disabled="saving" data-testid="grant-save">
              {{ saving ? "Saving…" : isEdit ? "Save changes" : "Create grant" }}
            </button>
          </div>
        </form>

        <GrantEvaluateTester
          v-if="isEdit && savedGrant && savedGrant.status !== 'DELETED' && name"
          ref="tester"
          :consumer-id="consumerId"
          :name="name"
          :saved-version="savedGrant.version"
          :dirty="dirty"
          :key-algorithms="testerAlgorithms"
        />
        <p v-else-if="!isEdit" class="notice notice-info" data-testid="tester-disabled">
          Testing becomes available once the grant is saved: it evaluates the saved grant.
        </p>
      </template>
    </div>

    <div
      v-if="confirmingDelete"
      class="modal-scrim"
      role="dialog"
      aria-modal="true"
      aria-labelledby="grant-delete-title"
      @keydown.esc="confirmingDelete = false"
    >
      <div class="modal-panel max-w-md">
        <h2 id="grant-delete-title" class="text-[17px] font-semibold">Delete this grant?</h2>
        <p class="mono mt-2 text-xs">{{ name }}</p>
        <p class="mt-2 text-[13px] text-ink-2">
          Deleting does not revoke certificates. Certificates this grant already issued stay
          valid until they expire or are revoked. A deleted grant cannot be restored; creating
          the name again makes a new grant.
        </p>
        <div class="mt-5 flex justify-end gap-2">
          <button class="btn" @click="confirmingDelete = false">Cancel</button>
          <button class="btn btn-danger" data-testid="grant-delete-confirm" @click="confirmDelete">Delete grant</button>
        </div>
      </div>
    </div>

    <BulkRevokeDialog
      v-if="revokingAfterDelete && deletedGrant"
      :consumer-id="consumerId"
      :grants="[deletedGrant]"
      :preset="{ issuanceGrant: deletedGrant.name, issuanceGrantUid: deletedGrant.uid }"
      @done="revokingAfterDelete = false"
      @close="revokingAfterDelete = false"
    />
  </div>
</template>
