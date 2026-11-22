/**
 * CloudWatch metric-name contract for the PKI alarms in cdk/stack.ts, plus an Embedded Metric Format emitter. EMF is
 * written to stdout and needs no IAM. Maintenance emits the count metrics every pass (0 when healthy); the issuer and
 * admin handlers emit +1 events.
 */
export const PKI_METRIC_NAMESPACE = "Hemlig/PKI";
export const PKI_METRIC_DIMENSION = "Deployment";

export const PKI_METRICS = {
  generatedCrlStale: "GeneratedCrlStale",
  externalCrlStale: "ExternalCrlStale",
  externalCrlMissing: "ExternalCrlMissing",
  caExpiring: "CaExpiring",
  caCapacityHigh: "CaCapacityHigh",
  crlOverCapacity: "CrlOverCapacity",
  caKeyUnavailable: "CaKeyUnavailable",
  kmsAccessDenied: "KmsAccessDenied",
} as const;

export type PkiMetricName = (typeof PKI_METRICS)[keyof typeof PKI_METRICS];

export const emitPkiMetrics = (
  deployment: string,
  values: Partial<Record<PkiMetricName, number>>,
  write: (line: string) => void = (line) => {
    process.stdout.write(line);
  },
): void => {
  const names = Object.keys(values);
  if (names.length === 0) {
    return;
  }
  write(
    `${JSON.stringify({
      _aws: {
        Timestamp: Date.now(),
        CloudWatchMetrics: [
          {
            Namespace: PKI_METRIC_NAMESPACE,
            Dimensions: [[PKI_METRIC_DIMENSION]],
            Metrics: names.map((name) => ({ Name: name, Unit: "Count" })),
          },
        ],
      },
      [PKI_METRIC_DIMENSION]: deployment,
      ...values,
    })}\n`,
  );
};
