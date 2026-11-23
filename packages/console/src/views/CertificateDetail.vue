<script setup lang="ts">
import { useQuery, useQueryClient } from "@tanstack/vue-query";
import { computed, ref } from "vue";
import CertificateRevokeDialog from "../components/CertificateRevokeDialog.vue";
import CopyField from "../components/CopyField.vue";
import ErrorNotice from "../components/ErrorNotice.vue";
import StateBadge from "../components/StateBadge.vue";
import { PKI_QUERY_OPTIONS, pkiKeys } from "../api/pki-query";
import type { PkiRevokeCertificateResponse } from "../api/pki-schemas";
import { useAppStore } from "../stores/app";

const props = defineProps<{ env: string; caId: string; serial: string }>();
const store = useAppStore();
const queryClient = useQueryClient();

const certificate = useQuery({
  ...PKI_QUERY_OPTIONS,
  queryKey: computed(() => pkiKeys.certificate(props.caId, props.serial)),
  queryFn: () => store.requireApi().getPkiCertificate(props.caId, props.serial),
});

const revoking = ref(false);

const detail = computed(() => certificate.data.value);

/** What the operator can still do to this certificate. */
const action = computed<"revoke" | "upgrade" | undefined>(() => {
  const cert = detail.value;
  if (cert === undefined || cert.childCaId !== undefined) {
    return undefined;
  }
  if (cert.storedStatus === "ISSUED") {
    return "revoke";
  }
  return cert.revocation !== undefined && cert.revocation.reason !== "keyCompromise"
    ? "upgrade"
    : undefined;
});

const sans = computed(() => [
  ...(detail.value?.sans.dns ?? []),
  ...(detail.value?.sans.ip ?? []),
  ...(detail.value?.sans.uri ?? []),
]);

const kubernetes = computed(() => detail.value?.requester.asserted?.kubernetes);

const onRevoked = (result: PkiRevokeCertificateResponse): void => {
  // The response already carries the updated certificate; storing it avoids a
  // second audited read.
  queryClient.setQueryData(pkiKeys.certificate(props.caId, props.serial), result.certificate);
  void queryClient.invalidateQueries({ queryKey: ["pki", "ca-certificates", props.caId] });
  void queryClient.invalidateQueries({ queryKey: ["pki", "consumer-certificates"] });
};
</script>

<template>
  <div>
    <div class="page-header">
      <div>
        <RouterLink
          class="link text-xs"
          :to="{ name: 'pki-ca', params: { env, caId }, query: { tab: 'certificates' } }"
        >
          ← {{ caId }}
        </RouterLink>
        <h1 class="page-title mono">{{ serial }}</h1>
      </div>
      <div class="page-actions">
        <button
          v-if="action"
          class="btn btn-danger"
          data-testid="revoke-open"
          @click="revoking = true"
        >
          {{ action === "revoke" ? "Revoke" : "Upgrade to keyCompromise" }}
        </button>
      </div>
    </div>

    <div class="space-y-4">
      <ErrorNotice v-if="certificate.error.value" :error="certificate.error.value" />

      <template v-if="detail">
        <section class="card card-body">
          <dl class="facts">
            <dt>Status</dt>
            <dd>
              <StateBadge :state="detail.status" />
              <span v-if="detail.storedStatus !== detail.status" class="field-hint ml-1">
                stored <StateBadge :state="detail.storedStatus" />
              </span>
            </dd>
            <dt>Subject</dt>
            <dd class="mono break-all">{{ detail.subject }}</dd>
            <dt>Names</dt>
            <dd class="mono break-all">{{ sans.join(", ") || "none" }}</dd>
            <dt>Key</dt>
            <dd class="mono">{{ detail.keyAlgorithm }}</dd>
            <dt>Valid</dt>
            <dd class="mono">
              {{ detail.notBefore }} to {{ detail.notAfter }}
              <span v-if="detail.lifetimeClamped" class="tag tag-warning ml-1">lifetime clamped</span>
            </dd>
            <dt>Issued</dt>
            <dd class="mono">{{ detail.issuedAt }}</dd>
            <dt>Fingerprint</dt>
            <dd class="mono break-all">{{ detail.fingerprint }}</dd>
            <dt>SPKI SHA-256</dt>
            <dd class="mono break-all">{{ detail.spkiSha256 }}</dd>
            <dt>Key usages</dt>
            <dd class="mono">{{ detail.keyUsages.join(", ") || "none" }}</dd>
            <dt>Extended key usages</dt>
            <dd class="mono">{{ detail.extendedKeyUsages.join(", ") || "none" }}</dd>
            <dt>Requested by</dt>
            <dd>
              {{ detail.requester.type }}
              <span class="mono">{{ detail.requester.id }}</span>
              <template v-if="detail.requester.issuanceGrant?.name">
                via grant
                <RouterLink
                  v-if="detail.requester.consumerId"
                  class="link mono"
                  :to="{
                    name: 'consumer-pki-grant',
                    params: {
                      env,
                      consumerId: detail.requester.consumerId,
                      name: detail.requester.issuanceGrant.name,
                    },
                  }"
                >{{ detail.requester.issuanceGrant.name }}</RouterLink>
                <span v-else class="mono">{{ detail.requester.issuanceGrant.name }}</span>
              </template>
            </dd>
            <template v-if="kubernetes">
              <dt>Kubernetes (caller-asserted)</dt>
              <dd class="mono break-all">
                {{ kubernetes.namespace }}/{{ kubernetes.name }}
                <span v-if="kubernetes.certificateName">, Certificate {{ kubernetes.certificateName }}</span>
                <span class="field-hint block">
                  caller-asserted: the requester supplied this; Hemlig did not verify it.
                </span>
              </dd>
            </template>
            <template v-if="detail.childCaId">
              <dt>Child CA</dt>
              <dd>
                <RouterLink
                  class="link mono"
                  :to="{ name: 'pki-ca', params: { env, caId: detail.childCaId } }"
                >{{ detail.childCaId }}</RouterLink>
                <span class="field-hint block">
                  This is a CA certificate. Manage it from its CA page, not here.
                </span>
              </dd>
            </template>
            <template v-if="detail.revocation">
              <dt>Revoked</dt>
              <dd class="mono">
                {{ detail.revocation.at }}, reason {{ detail.revocation.reason }}
                <span v-if="detail.revocation.invalidityDate">
                  , invalid since {{ detail.revocation.invalidityDate }}
                </span>
                <span v-if="detail.revocation.upgradedAt">
                  , upgraded {{ detail.revocation.upgradedAt }}
                </span>
              </dd>
            </template>
          </dl>
        </section>

        <section class="card card-body">
          <CopyField
            label="Certificate"
            :value="detail.certificatePem"
            multiline
            :filename="`${detail.serial}.crt.pem`"
          />
        </section>
      </template>
    </div>

    <CertificateRevokeDialog
      v-if="revoking && detail"
      :certificate="detail"
      @revoked="onRevoked"
      @close="revoking = false"
    />
  </div>
</template>
