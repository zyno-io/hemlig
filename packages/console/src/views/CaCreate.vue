<script setup lang="ts">
import { useQuery } from "@tanstack/vue-query";
import { computed, reactive, ref, watch } from "vue";
import CopyField from "../components/CopyField.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import MutationState from "../components/MutationState.vue";
import { ApiError } from "../api/errors";
import {
  CA_KEY_ALGORITHMS,
  ED25519_WARNING,
  EXTERNAL_ROOT_RECOMMENDATION,
  LEAF_KEY_ALGORITHMS,
  formatDuration,
  parseDuration,
} from "../api/pki-format";
import { fetchAllPages, PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import type {
  PkiCaDetail,
  PkiCaKind,
  PkiCaPolicyInput,
  PkiCaSummary,
  PkiCreateCaInput,
  PkiKeyAlgorithm,
  PkiLeafKeyAlgorithm,
  PkiNameSubtrees,
  PkiRequestedConstraints,
} from "../api/pki-schemas";
import {
  SUBJECT_ORDER,
  canonicalSubject,
  rolloverSuggestion,
  subjectProblems,
  type SubjectField,
} from "../api/pki-subject";
import { useGuardedMutation } from "../composables/useGuardedMutation";
import { useAppStore } from "../stores/app";

const props = defineProps<{
  env: string;
  rolloverFrom?: string | undefined;
  kind?: PkiCaKind | undefined;
}>();
const store = useAppStore();

const MAX_ISSUANCE_BUDGET = 12_000;
const DEFAULT_CAPACITY = 8_000;
const DEFAULT_PER_HOUR = 2_000;
const NAME_PATTERN = /^[a-z][a-z0-9-]{2,63}$/;
const DEFAULT_VALIDITY: Partial<Record<PkiCaKind, string>> = {
  ROOT: "3650d",
  INTERMEDIATE: "1825d",
};

const KIND_LABEL: Record<PkiCaKind, string> = {
  EXTERNAL_INTERMEDIATE: "Intermediate signed by your offline root (recommended)",
  INTERMEDIATE: "Intermediate signed by a Hemlig root",
  ROOT: "Root held by Hemlig (not recommended)",
};

const KIND_HINT: Record<PkiCaKind, string> = {
  EXTERNAL_INTERMEDIATE:
    "Hemlig creates the key and a CSR. You sign the CSR with your root and paste back the certificate.",
  INTERMEDIATE: "Hemlig signs it with a root it already holds.",
  ROOT: "Hemlig creates a self-signed root online. Prefer an offline root.",
};

/** Display order of the kind picker (recommended first); independent of the API enum order. */
const KIND_DISPLAY_ORDER: readonly PkiCaKind[] = ["EXTERNAL_INTERMEDIATE", "INTERMEDIATE", "ROOT"];

type SubtreeText = Record<keyof PkiNameSubtrees, string>;
const emptySubtrees = (): SubtreeText => ({ dns: "", ip: "", uri: "" });

const form = reactive({
  kind: (props.kind ?? "EXTERNAL_INTERMEDIATE") as PkiCaKind,
  name: "",
  displayName: "",
  keyAlgorithm: "ECDSA_P256" as PkiKeyAlgorithm,
  parentCaId: "",
  validity: "",
  subject: {} as Partial<Record<SubjectField, string>>,
  permitted: emptySubtrees(),
  excluded: emptySubtrees(),
  serverAuth: false,
  clientAuth: false,
  maxLeaf: "",
  leafAlgorithms: [] as PkiLeafKeyAlgorithm[],
  capacity: "",
  perHour: "",
  crlValidity: "",
});
const rootAcknowledged = ref(false);

const isHemligSigned = computed(() => form.kind !== "EXTERNAL_INTERMEDIATE");
const isRoot = computed(() => form.kind === "ROOT");

watch(
  () => form.kind,
  (kind) => {
    if (form.validity === "" && DEFAULT_VALIDITY[kind] !== undefined) {
      form.validity = DEFAULT_VALIDITY[kind] ?? "";
    }
    if (kind !== "ROOT") {
      rootAcknowledged.value = false;
    }
  },
  { immediate: true },
);

// ------------------------------------------------------------ Rollover

const base = useQuery({
  queryKey: computed(() => pkiKeys.ca(props.rolloverFrom ?? "")),
  queryFn: () => store.requireApi().getPkiCa(props.rolloverFrom ?? ""),
  enabled: computed(() => props.rolloverFrom !== undefined),
  ...PKI_QUERY_OPTIONS,
});
const baseCa = computed(() => base.data.value);
const environmentMismatch = computed(
  () => baseCa.value !== undefined && baseCa.value.environment !== props.env,
);

const lines = (items: readonly string[] | undefined): string =>
  (items ?? []).join("\n");

const prefill = (ca: PkiCaDetail): void => {
  const suggestion = rolloverSuggestion(ca);
  form.kind = ca.kind;
  form.keyAlgorithm = ca.keyAlgorithm;
  form.name = suggestion.name;
  form.subject = {
    commonName: suggestion.commonName,
    organization: ca.subject.organization,
    organizationalUnit: ca.subject.organizationalUnit,
    country: ca.subject.country,
    locality: ca.subject.locality,
    state: ca.subject.state,
  };
  if (ca.kind === "INTERMEDIATE") {
    form.parentCaId = ca.parentCaId ?? "";
  }
  if (ca.kind !== "EXTERNAL_INTERMEDIATE") {
    const seconds =
      ca.notBefore !== undefined && ca.notAfter !== undefined
        ? Math.round((Date.parse(ca.notAfter) - Date.parse(ca.notBefore)) / 1000)
        : 0;
    form.validity =
      seconds > 0 ? formatDuration(seconds) : (DEFAULT_VALIDITY[ca.kind] ?? "");
  }
  const constraints = ca.requestedConstraints;
  const permitted = constraints.nameConstraints?.permitted;
  const excluded = constraints.nameConstraints?.excluded;
  form.permitted = {
    dns: lines(permitted?.dns),
    ip: lines(permitted?.ip),
    uri: lines(permitted?.uri),
  };
  form.excluded = {
    dns: lines(excluded?.dns),
    ip: lines(excluded?.ip),
    uri: lines(excluded?.uri),
  };
  form.serverAuth = constraints.extendedKeyUsages?.includes("serverAuth") ?? false;
  form.clientAuth = constraints.extendedKeyUsages?.includes("clientAuth") ?? false;
  if (ca.kind !== "ROOT") {
    form.maxLeaf = formatDuration(ca.policy.maxLeafLifetimeSeconds);
    form.leafAlgorithms = ca.policy.leafKeyAlgorithms.filter(
      (algorithm): algorithm is PkiLeafKeyAlgorithm =>
        (LEAF_KEY_ALGORITHMS as readonly string[]).includes(algorithm),
    );
  }
  form.capacity = String(ca.policy.capacity);
  form.perHour = String(ca.policy.issuancePerHour);
  form.crlValidity = formatDuration(ca.policy.crlValiditySeconds);
};

let prefilled = false;
watch(
  baseCa,
  (ca) => {
    if (ca !== undefined && !prefilled && ca.environment === props.env) {
      prefilled = true;
      prefill(ca);
    }
  },
  { immediate: true },
);

// -------------------------------------------------------- Parent roots

const roots = useQuery({
  queryKey: computed(() => pkiKeys.cas(props.env)),
  queryFn: () =>
    fetchAllPages<PkiCaSummary>(async (cursor) => {
      const page = await store
        .requireApi()
        .listPkiCas({ environment: props.env, cursor });
      return { items: page.cas, nextCursor: page.nextCursor };
    }),
  enabled: computed(() => form.kind === "INTERMEDIATE"),
  ...PKI_QUERY_OPTIONS,
});
const activeRoots = computed(() =>
  (roots.data.value ?? []).filter((ca) => ca.kind === "ROOT" && ca.status === "ACTIVE"),
);

// ---------------------------------------------------------- Validation

const nameProblem = computed(() => {
  if (form.name === "") {
    return "Name is required.";
  }
  if (!NAME_PATTERN.test(form.name)) {
    return "Use 3-64 lowercase letters, digits and hyphens, starting with a letter.";
  }
  if (baseCa.value !== undefined && form.name === baseCa.value.name) {
    return "That is the base CA's name. CA names are never reused.";
  }
  return undefined;
});

const fieldProblems = computed(() => subjectProblems(form.subject, form.kind));

const subjectReused = computed(
  () =>
    baseCa.value !== undefined &&
    canonicalSubject(form.subject) === canonicalSubject(baseCa.value.subject),
);

const parseCount = (text: string): number | undefined =>
  /^\d+$/.test(text.trim()) ? Number(text.trim()) : undefined;

const policyProblems = computed(() => {
  const problems: string[] = [];
  if (form.maxLeaf !== "" && parseDuration(form.maxLeaf) === undefined) {
    problems.push("Max leaf lifetime must look like 90d, 12h, 30m or 600s.");
  }
  if (form.crlValidity !== "" && parseDuration(form.crlValidity) === undefined) {
    problems.push("CRL validity must look like 7d.");
  }
  if (form.capacity !== "" && parseCount(form.capacity) === undefined) {
    problems.push("Capacity must be a whole number.");
  }
  if (form.perHour !== "" && parseCount(form.perHour) === undefined) {
    problems.push("Issuance per hour must be a whole number.");
  }
  return problems;
});

const budget = computed(
  () =>
    (parseCount(form.capacity) ?? DEFAULT_CAPACITY) +
    2 * (parseCount(form.perHour) ?? DEFAULT_PER_HOUR),
);
const budgetExceeded = computed(() => budget.value > MAX_ISSUANCE_BUDGET);

const validityProblem = computed(() => {
  if (!isHemligSigned.value) {
    return undefined;
  }
  return form.validity === "" || parseDuration(form.validity) === undefined
    ? "Validity is required, for example 3650d."
    : undefined;
});

const parentProblem = computed(() =>
  form.kind === "INTERMEDIATE" && form.parentCaId === ""
    ? "Choose an active root."
    : undefined,
);

const blocked = computed(
  () =>
    nameProblem.value !== undefined ||
    Object.keys(fieldProblems.value).length > 0 ||
    subjectReused.value ||
    environmentMismatch.value ||
    budgetExceeded.value ||
    policyProblems.value.length > 0 ||
    validityProblem.value !== undefined ||
    parentProblem.value !== undefined ||
    (isRoot.value && !rootAcknowledged.value) ||
    (props.rolloverFrom !== undefined && baseCa.value === undefined),
);

// -------------------------------------------------------------- Submit

const splitLines = (text: string): string[] =>
  text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "");

const subtrees = (text: SubtreeText): PkiNameSubtrees | undefined => {
  const result: PkiNameSubtrees = {
    ...(splitLines(text.dns).length > 0 ? { dns: splitLines(text.dns) } : {}),
    ...(splitLines(text.ip).length > 0 ? { ip: splitLines(text.ip) } : {}),
    ...(splitLines(text.uri).length > 0 ? { uri: splitLines(text.uri) } : {}),
  };
  return Object.keys(result).length === 0 ? undefined : result;
};

const buildInput = (): PkiCreateCaInput => {
  const subject: PkiCreateCaInput["subject"] = { commonName: form.subject.commonName ?? "" };
  if (form.subject.organization) subject.organization = form.subject.organization;
  if (form.subject.organizationalUnit) {
    subject.organizationalUnit = form.subject.organizationalUnit;
  }
  if (form.subject.country) subject.country = form.subject.country;
  if (form.subject.locality) subject.locality = form.subject.locality;
  if (form.subject.state) subject.state = form.subject.state;

  const permitted = subtrees(form.permitted);
  const excluded = subtrees(form.excluded);
  const ekus = [
    ...(form.serverAuth ? (["serverAuth"] as const) : []),
    ...(form.clientAuth ? (["clientAuth"] as const) : []),
  ];
  const constraints: PkiRequestedConstraints = {
    ...(permitted !== undefined || excluded !== undefined
      ? {
          nameConstraints: {
            ...(permitted === undefined ? {} : { permitted }),
            ...(excluded === undefined ? {} : { excluded }),
          },
        }
      : {}),
    ...(ekus.length > 0 ? { extendedKeyUsages: [...ekus] } : {}),
  };

  // Blank policy fields are omitted so the server defaults apply.
  const policy: PkiCaPolicyInput = {};
  if (!isRoot.value) {
    if (form.maxLeaf !== "") policy.maxLeafLifetimeSeconds = parseDuration(form.maxLeaf);
    if (form.leafAlgorithms.length > 0) policy.leafKeyAlgorithms = [...form.leafAlgorithms];
  }
  if (form.capacity !== "") policy.capacity = parseCount(form.capacity);
  if (form.perHour !== "") policy.issuancePerHour = parseCount(form.perHour);
  if (form.crlValidity !== "") policy.crlValiditySeconds = parseDuration(form.crlValidity);

  const validitySeconds = isHemligSigned.value ? parseDuration(form.validity) : undefined;
  return {
    environment: props.env,
    name: form.name,
    kind: form.kind,
    keyAlgorithm: form.keyAlgorithm,
    subject,
    ...(form.kind === "INTERMEDIATE" ? { parentCaId: form.parentCaId } : {}),
    ...(validitySeconds === undefined ? {} : { validitySeconds }),
    ...(Object.keys(constraints).length > 0 ? { requestedConstraints: constraints } : {}),
    ...(Object.keys(policy).length > 0 ? { policy } : {}),
    ...(form.displayName.trim() === "" ? {} : { displayName: form.displayName.trim() }),
  };
};

const creation = useGuardedMutation<PkiCreateCaInput, PkiCaDetail>({
  family: "pki",
  mutate: (input, key) => store.requireApi().createPkiCa(input, key),
});

const submitting = computed(() => creation.phase.value.kind === "submitting");

const submit = async (): Promise<void> => {
  if (blocked.value || submitting.value) {
    return;
  }
  await creation.submit(buildInput());
};

const failure = computed(() => {
  const phase = creation.phase.value;
  return phase.kind === "failed" && phase.error instanceof ApiError
    ? phase.error
    : undefined;
});
const subjectInUse = computed(() => failure.value?.code === "ca_subject_in_use");
const nameInUse = computed(
  () => failure.value?.code === "conflict" && failure.value.reason === "name_in_use",
);

const toggleLeafAlgorithm = (algorithm: PkiLeafKeyAlgorithm): void => {
  form.leafAlgorithms = form.leafAlgorithms.includes(algorithm)
    ? form.leafAlgorithms.filter((item) => item !== algorithm)
    : [...form.leafAlgorithms, algorithm];
};

const SUBTREE_KEYS = ["dns", "ip", "uri"] as const;
const SUBTREE_GROUPS = [
  { key: "permitted", title: "Permitted" },
  { key: "excluded", title: "Excluded" },
] as const;
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <RouterLink class="link text-xs" :to="{ name: 'pki', params: { env } }">
          ← PKI
        </RouterLink>
        <h1 class="page-title">
          {{ rolloverFrom ? "Roll over a CA" : "New CA" }} in {{ env }}
        </h1>
        <p class="page-subtitle">
          CA names and subject names are never reused, so a rollover creates a new CA.
        </p>
      </div>
    </div>

    <div class="max-w-3xl space-y-4">
      <ErrorNotice v-if="base.error.value" :error="base.error.value" context="the base CA" />
      <p v-if="environmentMismatch" class="notice notice-danger" role="alert">
        The base CA belongs to {{ baseCa?.environment }}, not {{ env }}. A rollover must stay in
        one environment.
      </p>

      <section
        v-if="creation.result.value"
        class="card card-body space-y-3"
        data-testid="create-success"
      >
        <h2 class="section-title">CA created</h2>
        <p class="text-[13px] text-ink-2">
          <span class="mono">{{ creation.result.value.name }}</span> is
          {{ creation.result.value.status }}.
        </p>
        <ul v-if="(creation.result.value.warnings ?? []).length > 0" class="space-y-2">
          <li
            v-for="warning in creation.result.value.warnings"
            :key="warning.code"
            class="notice notice-warning"
            data-testid="create-warning"
          >
            {{ warning.message }}
          </li>
        </ul>
        <CopyField
          v-if="creation.result.value.csrPem"
          label="Certificate request"
          :value="creation.result.value.csrPem"
          multiline
          :filename="`${creation.result.value.name}.csr.pem`"
        />
        <RouterLink
          class="btn btn-primary"
          :to="{ name: 'pki-ca', params: { env, caId: creation.result.value.caId } }"
        >
          Continue to CA
        </RouterLink>
      </section>

      <form v-else class="space-y-4" @submit.prevent="submit">
        <section class="card card-body space-y-3">
          <h2 class="section-title">Kind</h2>
          <fieldset class="space-y-1">
            <label v-for="kind in KIND_DISPLAY_ORDER" :key="kind" class="flex items-start gap-2 text-[13px]" :data-testid="`kind-${kind}`">
              <input v-model="form.kind" type="radio" name="kind" :value="kind" class="mt-[3px]" />
              <span>
                {{ KIND_LABEL[kind] }}
                <span class="block text-[13px] text-ink-2">{{ KIND_HINT[kind] }}</span>
              </span>
            </label>
          </fieldset>
          <div v-if="isRoot" class="notice notice-warning" data-testid="root-callout">
            <p>{{ EXTERNAL_ROOT_RECOMMENDATION }}</p>
            <p class="mt-1">
              <a
                class="link"
                href="https://zyno-io.github.io/hemlig/operations/pki-offline-root.html"
                target="_blank"
                rel="noopener noreferrer"
              >Offline root guide</a>
            </p>
            <label class="mt-2 flex items-start gap-2">
              <input v-model="rootAcknowledged" type="checkbox" data-testid="root-ack" />
              <span>I understand and want an online root anyway.</span>
            </label>
          </div>
        </section>

        <section class="card card-body space-y-3">
          <h2 class="section-title">Identity</h2>
          <label class="block">
            <span class="field-label">Name</span>
            <input v-model="form.name" class="input mono" data-testid="ca-name" autocomplete="off" />
            <span v-if="nameInUse" class="field-error block">
              That CA name is already taken. CA names are never reused.
            </span>
            <span v-else-if="nameProblem && form.name !== ''" class="field-error block">
              {{ nameProblem }}
            </span>
          </label>
          <label class="block">
            <span class="field-label">Display name (optional)</span>
            <input v-model="form.displayName" class="input" maxlength="128" />
          </label>
          <label class="block">
            <span class="field-label">Key algorithm</span>
            <select v-model="form.keyAlgorithm" class="input" data-testid="ca-algorithm">
              <option v-for="algorithm in CA_KEY_ALGORITHMS" :key="algorithm" :value="algorithm">
                {{ algorithm }}
              </option>
            </select>
          </label>
          <p
            v-if="form.keyAlgorithm === 'ED25519'"
            class="notice notice-warning"
            data-testid="ed25519-warning"
          >
            {{ ED25519_WARNING }}
          </p>

          <label v-if="form.kind === 'INTERMEDIATE'" class="block">
            <span class="field-label">Parent root</span>
            <select v-model="form.parentCaId" class="input" data-testid="ca-parent">
              <option value="">Select an active root</option>
              <option v-for="root in activeRoots" :key="root.caId" :value="root.caId">
                {{ root.name }}
              </option>
            </select>
            <span v-if="roots.data.value && activeRoots.length === 0" class="field-hint block">
              No ROOT CA is active in {{ env }}.
            </span>
          </label>
          <label v-if="isHemligSigned" class="block">
            <span class="field-label">Validity</span>
            <input
              v-model="form.validity"
              class="input mono"
              placeholder="3650d"
              data-testid="ca-validity"
            />
            <span v-if="validityProblem" class="field-error block">{{ validityProblem }}</span>
          </label>
        </section>

        <section class="card card-body space-y-3">
          <h2 class="section-title">Subject</h2>
          <p class="field-hint">
            Printable ASCII, no leading, trailing or doubled spaces. Names that differ only in
            case or spacing are the same name.
          </p>
          <label v-for="item in SUBJECT_ORDER" :key="item.field" class="block">
            <span class="field-label">{{ item.label }}</span>
            <input
              v-model="form.subject[item.field]"
              class="input"
              :data-testid="`subject-${item.field}`"
              autocomplete="off"
            />
            <span v-if="fieldProblems[item.field]" class="field-error block">
              {{ fieldProblems[item.field] }}
            </span>
          </label>
          <p v-if="subjectReused" class="field-error" role="alert" data-testid="subject-reused">
            This subject is the same as the base CA's. Subject names are never reused, so change
            the common name.
          </p>
          <p v-if="subjectInUse" class="field-error" role="alert">
            That subject name is already claimed. Subject names are never reused.
          </p>
        </section>

        <section class="card card-body space-y-3">
          <h2 class="section-title">Constraints</h2>
          <div class="grid gap-3 sm:grid-cols-2">
            <div v-for="group in SUBTREE_GROUPS" :key="group.key">
              <p class="field-label">{{ group.title }} names</p>
              <label v-for="key in SUBTREE_KEYS" :key="key" class="mt-1 block">
                <span class="field-hint">{{ key.toUpperCase() }}, one per line</span>
                <textarea
                  v-model="form[group.key][key]"
                  class="input mono"
                  rows="2"
                  spellcheck="false"
                  :aria-label="`${group.title} ${key}`"
                />
              </label>
            </div>
          </div>
          <fieldset class="flex gap-4 text-[13px]">
            <legend class="field-label">Extended key usages</legend>
            <label class="flex items-center gap-1">
              <input v-model="form.serverAuth" type="checkbox" /> serverAuth
            </label>
            <label class="flex items-center gap-1">
              <input v-model="form.clientAuth" type="checkbox" /> clientAuth
            </label>
          </fieldset>
        </section>

        <section class="card card-body space-y-3">
          <h2 class="section-title">Policy</h2>
          <p class="field-hint">Leave a field blank to use the server default.</p>
          <template v-if="!isRoot">
            <label class="block">
              <span class="field-label">Max leaf lifetime</span>
              <input
                v-model="form.maxLeaf"
                class="input mono"
                placeholder="90d"
                data-testid="policy-max-leaf"
              />
            </label>
            <fieldset class="space-y-1" data-testid="leaf-algorithms">
              <legend class="field-label">Leaf key algorithms</legend>
              <div class="flex flex-wrap gap-3 text-[13px]">
                <label v-for="algorithm in LEAF_KEY_ALGORITHMS" :key="algorithm" class="flex items-center gap-1">
                  <input
                    type="checkbox"
                    :checked="form.leafAlgorithms.includes(algorithm)"
                    @change="toggleLeafAlgorithm(algorithm)"
                  />
                  {{ algorithm }}
                </label>
              </div>
            </fieldset>
          </template>
          <div class="grid gap-3 sm:grid-cols-3">
            <label class="block">
              <span class="field-label">Capacity</span>
              <input v-model="form.capacity" class="input mono" placeholder="8000" data-testid="policy-capacity" />
            </label>
            <label class="block">
              <span class="field-label">Issuance per hour</span>
              <input v-model="form.perHour" class="input mono" placeholder="2000" data-testid="policy-per-hour" />
            </label>
            <label class="block">
              <span class="field-label">CRL validity</span>
              <input v-model="form.crlValidity" class="input mono" placeholder="7d" />
            </label>
          </div>
          <p v-if="budgetExceeded" class="field-error" role="alert" data-testid="budget-error">
            capacity + 2 × issuance per hour must not exceed 12,000 (now {{ budget }}).
          </p>
          <ul v-if="policyProblems.length > 0" class="field-error">
            <li v-for="problem in policyProblems" :key="problem">{{ problem }}</li>
          </ul>
        </section>

        <MutationState
          :phase="creation.phase.value"
          :can-retry="creation.canRetry.value"
          family="pki"
          intent="create this CA"
          @retry="creation.retry()"
          @reload="creation.reset()"
        />

        <div>
          <button
            type="submit"
            class="btn btn-primary"
            data-testid="create-submit"
            :disabled="blocked || submitting"
          >
            {{ submitting ? "Creating…" : "Create CA" }}
          </button>
        </div>
      </form>
    </div>
  </div>
</template>
