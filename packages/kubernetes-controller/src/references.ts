import type { HemligConsumer } from "./v1beta";

export const consumerReferenceKey = (
  resourceNamespace: string,
  consumerRef: string,
  consumerNamespace?: string,
): string => `${consumerNamespace ?? resourceNamespace}/${consumerRef}`;

export const allowsConsumerReference = (
  resourceNamespace: string,
  consumerNamespace: string | undefined,
  consumer: HemligConsumer | undefined,
): boolean =>
  consumerNamespace === undefined ||
  consumerNamespace === resourceNamespace ||
  consumer?.spec.allowCrossNamespaceReferences === true;

/** True when every `matchLabels` entry is present on the namespace's labels. */
export const namespaceMatches = (
  labels: Readonly<Record<string, string>> | undefined,
  matchLabels: Readonly<Record<string, string>>,
): boolean =>
  Object.entries(matchLabels).every(([key, value]) => labels?.[key] === value);
