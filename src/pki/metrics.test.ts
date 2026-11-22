import { emitPkiMetrics, PKI_METRIC_NAMESPACE, PKI_METRICS } from "./metrics";

describe("emitPkiMetrics", () => {
  it("writes one EMF document per call", () => {
    const lines: string[] = [];
    emitPkiMetrics(
      "prod",
      { [PKI_METRICS.caExpiring]: 0, [PKI_METRICS.kmsAccessDenied]: 1 },
      (line) => lines.push(line),
    );
    expect(lines).toHaveLength(1);
    expect(lines[0]?.endsWith("\n")).toBe(true);
    expect(lines[0]?.trim().split("\n")).toHaveLength(1);
    const document = JSON.parse(lines[0] ?? "") as Record<string, any>;
    expect(document._aws.CloudWatchMetrics).toEqual([
      {
        Namespace: PKI_METRIC_NAMESPACE,
        Dimensions: [["Deployment"]],
        Metrics: [
          { Name: "CaExpiring", Unit: "Count" },
          { Name: "KmsAccessDenied", Unit: "Count" },
        ],
      },
    ]);
    expect(typeof document._aws.Timestamp).toBe("number");
    expect(document).toMatchObject({
      Deployment: "prod",
      CaExpiring: 0,
      KmsAccessDenied: 1,
    });
    expect(PKI_METRIC_NAMESPACE).toBe("Hemlig/PKI");
  });

  it("writes nothing when there are no values", () => {
    const write = jest.fn();
    emitPkiMetrics("prod", {}, write);
    expect(write).not.toHaveBeenCalled();
  });
});
