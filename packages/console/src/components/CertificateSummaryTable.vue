<script setup lang="ts">
import type { PkiCertificateSummary } from "../api/pki-schemas";
import StateBadge from "./StateBadge.vue";

defineProps<{
  env: string;
  certificates: readonly PkiCertificateSummary[];
  /** Adds a CA column, for lists that span several CAs. */
  showCa?: boolean;
}>();

const MAX_SANS = 3;

const allSans = (certificate: PkiCertificateSummary): string[] => [
  ...(certificate.sans.dns ?? []),
  ...(certificate.sans.ip ?? []),
  ...(certificate.sans.uri ?? []),
];
</script>

<template>
  <table class="data-table">
    <thead>
      <tr>
        <th>Serial</th>
        <th v-if="showCa">CA</th>
        <th>Status</th>
        <th>Names</th>
        <th>Expires</th>
        <th>Grant</th>
      </tr>
    </thead>
    <tbody>
      <tr v-for="certificate in certificates" :key="`${certificate.caId}/${certificate.serial}`">
        <td>
          <RouterLink
            class="mono"
            :to="{
              name: 'pki-certificate',
              params: { env, caId: certificate.caId, serial: certificate.serial },
            }"
          >{{ certificate.serial }}</RouterLink>
        </td>
        <td v-if="showCa" class="mono">{{ certificate.caId }}</td>
        <td>
          <StateBadge :state="certificate.status" />
          <span
            v-if="certificate.storedStatus !== certificate.status"
            class="field-hint ml-1"
          >stored <StateBadge :state="certificate.storedStatus" /></span>
        </td>
        <td>
          <template v-for="(san, index) in allSans(certificate).slice(0, MAX_SANS)" :key="san">
            <span v-if="index > 0">, </span><span class="mono">{{ san }}</span>
          </template>
          <span v-if="allSans(certificate).length > MAX_SANS" class="field-hint">
            +{{ allSans(certificate).length - MAX_SANS }}
          </span>
          <span v-if="allSans(certificate).length === 0" class="field-hint">
            {{ certificate.subject }}
          </span>
        </td>
        <td>{{ certificate.notAfter }}</td>
        <td>
          <span v-if="certificate.requester.issuanceGrant?.name" class="mono">
            {{ certificate.requester.issuanceGrant.name }}
          </span>
          <span v-else class="field-hint">{{ certificate.requester.type }}</span>
        </td>
      </tr>
    </tbody>
  </table>
</template>
