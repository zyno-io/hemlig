import { newKey, subjectDer } from "../__fixtures__/testkit";
import { verifySignature } from "./algorithms";
import { buildExternalIntermediateCsr, parseRawCsr } from "./csr";
import { EKU, EXT, decodeExtensions } from "./extensions";
import { children } from "./der";
import { parseDer } from "./der";

describe("external intermediate CSR", () => {
  it("carries the constrained CA extensions and a valid signature", async () => {
    const key = await newKey("ECDSA_P384");
    const csr = await buildExternalIntermediateCsr({
      subjectDer: subjectDer({
        O: "Example Corp",
        CN: "Example Prod Issuing CA 1",
      }),
      spkiDer: key.spkiDer,
      keyAlgorithm: "ECDSA_P384",
      nameConstraints: {
        permitted: [
          { type: "dns", value: "example.com" },
          { type: "dns", value: "svc.cluster.local" },
        ],
        excluded: [],
      },
      extendedKeyUsage: [EKU.serverAuth, EKU.clientAuth],
      sign: async (info) => key.sign(info),
    });
    const raw = parseRawCsr(csr);
    expect(raw.version).toBe(0);
    expect(raw.attributes).toHaveLength(1);
    expect(raw.attributes[0]?.oid).toBe(EXT.extensionRequest);
    const extensions = decodeExtensions(
      raw.attributes[0]?.values[0] ?? parseDer(Buffer.from("3000", "hex")),
    );
    expect(
      extensions.map((extension) => [extension.oid, extension.critical]),
    ).toEqual([
      [EXT.basicConstraints, true],
      [EXT.keyUsage, true],
      [EXT.nameConstraints, true],
      [EXT.extendedKeyUsage, false],
      [EXT.subjectKeyIdentifier, false],
    ]);
    expect(extensions[0]?.value.toString("hex")).toBe("30060101ff020100");
    expect(extensions[1]?.value.toString("hex")).toBe("03020106");
    expect(
      verifySignature(
        raw.spkiDer,
        raw.signatureAlgorithm,
        raw.infoDer,
        raw.signature,
      ),
    ).toBe(true);
    expect(children(parseDer(raw.infoDer))).toHaveLength(4);
  });

  it("omits optional extensions when not requested", async () => {
    const key = await newKey();
    const csr = await buildExternalIntermediateCsr({
      subjectDer: subjectDer("Plain CA"),
      spkiDer: key.spkiDer,
      keyAlgorithm: "ECDSA_P256",
      sign: async (info) => key.sign(info),
    });
    const raw = parseRawCsr(csr);
    const extensions = decodeExtensions(
      raw.attributes[0]?.values[0] ?? parseDer(Buffer.from("3000", "hex")),
    );
    expect(extensions.map((extension) => extension.oid)).toEqual([
      EXT.basicConstraints,
      EXT.keyUsage,
      EXT.subjectKeyIdentifier,
    ]);
  });
});
