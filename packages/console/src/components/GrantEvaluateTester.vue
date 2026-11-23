<script setup lang="ts">
import { computed, ref } from "vue";
import ErrorNotice from "./ErrorNotice.vue";
import PemField from "./PemField.vue";
import StateBadge from "./StateBadge.vue";
import { parseDuration } from "../api/pki-format";
import { splitLines } from "../api/pki-grant-form";
import type {
  PkiEvaluateInput,
  PkiEvaluateResponse,
  PkiLeafKeyAlgorithm,
} from "../api/pki-schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{
  consumerId: string;
  name: string;
  savedVersion: string;
  /** The draft differs from the saved grant. */
  dirty: boolean;
  keyAlgorithms: readonly string[];
}>();

const store = useAppStore();

const USAGES = ["digitalSignature", "keyEncipherment", "serverAuth", "clientAuth"] as const;

const mode = ref<"names" | "csr">("names");
const keyAlgorithm = ref<string>(props.keyAlgorithms[0] ?? "ECDSA_P256");
const dns = ref("");
const ip = ref("");
const uri = ref("");
const commonName = ref("");
const duration = ref("");
const usages = ref<string[]>([]);
const csr = ref("");

const running = ref(false);
const result = ref<PkiEvaluateResponse | undefined>();
const failure = ref<unknown>();
const localProblem = ref<string | undefined>();
let lastInput: PkiEvaluateInput | undefined;

const buildInput = (): PkiEvaluateInput | undefined => {
  localProblem.value = undefined;
  let durationSeconds: number | undefined;
  if (duration.value.trim() !== "") {
    durationSeconds = parseDuration(duration.value);
    if (durationSeconds === undefined) {
      localProblem.value = "Duration must look like 3600s, 90m, 24h or 90d.";
      return undefined;
    }
  }
  const common: PkiEvaluateInput = {
    ...(durationSeconds === undefined ? {} : { durationSeconds }),
    ...(usages.value.length === 0 ? {} : { usages: [...usages.value] }),
  };
  if (mode.value === "csr") {
    if (csr.value.trim() === "") {
      localProblem.value = "Paste a CSR to test.";
      return undefined;
    }
    // A CSR carries its own names and key, so none of those are sent.
    return { certificateSigningRequestPem: csr.value.trim(), ...common };
  }
  const sans = {
    ...(splitLines(dns.value).length === 0 ? {} : { dns: splitLines(dns.value) }),
    ...(splitLines(ip.value).length === 0 ? {} : { ip: splitLines(ip.value) }),
    ...(splitLines(uri.value).length === 0 ? {} : { uri: splitLines(uri.value) }),
  };
  return {
    keyAlgorithm: keyAlgorithm.value as PkiLeafKeyAlgorithm,
    ...(Object.keys(sans).length === 0 ? {} : { sans }),
    ...(commonName.value.trim() === "" ? {} : { commonName: commonName.value.trim() }),
    ...common,
  };
};

const execute = async (input: PkiEvaluateInput): Promise<void> => {
  if (running.value) {
    return;
  }
  running.value = true;
  failure.value = undefined;
  try {
    result.value = await store
      .requireApi()
      .evaluateIssuanceGrant(props.consumerId, props.name, input);
    lastInput = input;
  } catch (caught) {
    failure.value = caught;
    result.value = undefined;
  } finally {
    running.value = false;
  }
};

/** Runs only on an explicit action: the button or Enter in the form. */
const run = async (): Promise<void> => {
  const input = buildInput();
  if (input !== undefined) {
    await execute(input);
  }
};

/** Re-runs the last test once, to show the effect of a save. */
const rerun = async (): Promise<void> => {
  if (lastInput !== undefined) {
    await execute(lastInput);
  }
};
defineExpose({ rerun });

const sanList = (plan: PkiEvaluateResponse["plan"]): string[] =>
  plan === undefined
    ? []
    : [...(plan.sans.dns ?? []), ...(plan.sans.ip ?? []), ...(plan.sans.uri ?? [])];

const algorithms = computed(() =>
  props.keyAlgorithms.length > 0 ? props.keyAlgorithms : ["ECDSA_P256"],
);
</script>

<template>
  <section class="card" aria-label="Evaluate">
    <div class="card-header">
      <div>
        <h2 class="section-title">Test this grant</h2>
        <p class="meta">
          Dry-runs a request against the saved grant. Each test writes one audited read
          event.
        </p>
      </div>
    </div>
    <div class="card-body space-y-3">
      <p v-if="dirty" class="notice notice-warning" role="status" data-testid="dirty-banner">
        Tests the saved grant (version {{ savedVersion }}). Save to test your changes.
      </p>

      <form class="space-y-3" @submit.prevent="run">
        <div class="flex gap-1" role="tablist">
          <button
            v-for="option in ['names', 'csr'] as const"
            :key="option"
            type="button"
            role="tab"
            class="btn btn-sm"
            :aria-selected="mode === option"
            :class="mode === option ? 'bg-surface-3! text-ink!' : ''"
            @click="mode = option"
          >
            {{ option === "names" ? "Names" : "CSR" }}
          </button>
        </div>

        <template v-if="mode === 'names'">
          <label class="block">
            <span class="field-label">Key algorithm</span>
            <select v-model="keyAlgorithm" class="input" data-testid="eval-algorithm">
              <option v-for="algorithm in algorithms" :key="algorithm" :value="algorithm">
                {{ algorithm }}
              </option>
            </select>
          </label>
          <div class="grid gap-3 sm:grid-cols-3">
            <label class="block">
              <span class="field-label">DNS names</span>
              <textarea v-model="dns" class="input mono text-xs" rows="2" data-testid="eval-dns" />
            </label>
            <label class="block">
              <span class="field-label">IP addresses</span>
              <textarea v-model="ip" class="input mono text-xs" rows="2" data-testid="eval-ip" />
            </label>
            <label class="block">
              <span class="field-label">URIs</span>
              <textarea v-model="uri" class="input mono text-xs" rows="2" data-testid="eval-uri" />
            </label>
          </div>
          <label class="block">
            <span class="field-label">Common name</span>
            <input v-model="commonName" class="input mono" data-testid="eval-cn" />
          </label>
        </template>
        <template v-else>
          <PemField v-model="csr" label="Certificate request" kind="csr" />
          <p class="field-hint">
            The names and key come from the CSR, so none are sent alongside it.
          </p>
        </template>

        <div class="grid gap-3 sm:grid-cols-2">
          <label class="block">
            <span class="field-label">Duration</span>
            <input
              v-model="duration"
              class="input mono"
              placeholder="e.g. 24h (grant default when empty)"
              data-testid="eval-duration"
            />
          </label>
          <fieldset>
            <legend class="field-label">Usages</legend>
            <label v-for="usage in USAGES" :key="usage" class="mr-3 inline-flex items-center gap-1 text-xs">
              <input v-model="usages" type="checkbox" :value="usage" />
              {{ usage }}
            </label>
          </fieldset>
        </div>

        <p v-if="localProblem" class="field-error" role="alert">{{ localProblem }}</p>
        <button type="submit" class="btn btn-primary" :disabled="running" data-testid="eval-run">
          {{ running ? "Testing…" : "Run test" }}
        </button>
      </form>

      <ErrorNotice v-if="failure" :error="failure" />

      <div v-if="result" class="space-y-3" data-testid="eval-result">
        <p class="flex items-center gap-2">
          <StateBadge :state="result.decision" />
          <span class="text-[13px]">
            {{ result.decision === "allow" ? "The grant would issue this certificate." : "The grant would refuse this request." }}
          </span>
        </p>

        <div v-if="result.denial" class="notice notice-danger" role="status">
          <p class="notice-title">Denied: <span class="mono">{{ result.denial.reason }}</span></p>
          <p class="mt-1">{{ result.denial.detail }}</p>
          <p v-if="result.denial.deniedName" class="mt-1 text-xs">
            Denied {{ result.denial.deniedNameType ?? "name" }}:
            <span class="mono text-ink">{{ result.denial.deniedName }}</span>
          </p>
        </div>

        <div v-if="result.plan">
          <h3 class="field-label">Plan</h3>
          <dl class="facts">
            <dt>Key algorithm</dt>
            <dd class="mono">{{ result.plan.keyAlgorithm }}</dd>
            <dt>Subject</dt>
            <dd class="mono break-all">{{ result.plan.subject }}</dd>
            <dt>SANs</dt>
            <dd class="mono break-all">
              {{ sanList(result.plan).join(", ") || "none" }}
              <span v-if="result.plan.sanCritical" class="tag tag-warning ml-1">critical</span>
            </dd>
            <dt>Key usages</dt>
            <dd class="mono">{{ result.plan.keyUsages.join(", ") }}</dd>
            <dt>Extended key usages</dt>
            <dd class="mono">{{ result.plan.extendedKeyUsages.join(", ") || "none" }}</dd>
            <dt>Valid</dt>
            <dd class="mono">
              {{ result.plan.notBefore }} to {{ result.plan.notAfter }}
              <span v-if="result.plan.lifetimeClamped" class="tag tag-warning ml-1">lifetime clamped</span>
            </dd>
          </dl>
        </div>

        <div class="overflow-x-auto">
          <table class="data-table">
            <thead>
              <tr><th>Step</th><th>Name</th><th>Outcome</th><th>Detail</th></tr>
            </thead>
            <tbody>
              <tr v-for="step in result.trace" :key="step.step">
                <td>{{ step.step }}</td>
                <td class="mono text-xs">{{ step.name }}</td>
                <td class="text-xs">{{ step.outcome }}</td>
                <td class="text-xs">{{ step.detail }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <dl class="facts">
          <dt>Grant</dt>
          <dd>
            <StateBadge :state="result.context.grant.status" />
            <span v-if="result.context.grant.expired" class="tag tag-warning ml-1">expired</span>
          </dd>
          <dt>CA</dt>
          <dd class="mono">{{ result.context.ca.status }} / key {{ result.context.ca.keyState }}</dd>
          <dt>Capacity</dt>
          <dd class="mono">{{ result.context.capacity.count ?? "?" }} / {{ result.context.capacity.capacity }}</dd>
          <dt>Quotas</dt>
          <dd class="mono text-xs">
            grant/hour {{ result.context.quotas.grantHour.count }}/{{ result.context.quotas.grantHour.limit }},
            grant/day {{ result.context.quotas.grantDay.count }}/{{ result.context.quotas.grantDay.limit }},
            CA/hour {{ result.context.quotas.caHour.count }}/{{ result.context.quotas.caHour.limit }}
          </dd>
        </dl>
      </div>
    </div>
  </section>
</template>
