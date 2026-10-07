# Hemlig licensing

Copyright (c) 2026 Signal24 LLC dba Zyno Consulting.

Author: Zyno Consulting <oss@zyno.io>.

Hemlig uses GNU Affero General Public License version 3 only
(`AGPL-3.0-only`) for the secrets service and administrator console, and MIT
for its clients and integrations. These are component licenses, not a choice
between licenses for the same server code.

| Component                                  | Paths                                                                          | License                  |
| ------------------------------------------ | ------------------------------------------------------------------------------ | ------------------------ |
| Secrets service                            | `src/`, `dist/` and other first-party material without a more specific license | [AGPL-3.0-only](LICENSE) |
| Administrator console                      | `packages/console/` and its built assets, including `dist-cdk/console-dist/`   | [AGPL-3.0-only](LICENSE) |
| Typed client                               | `packages/client/`                                                             | [MIT](LICENSE-MIT)       |
| Administrator CLI                          | `packages/cli/`                                                                | [MIT](LICENSE-MIT)       |
| Kubernetes controller, CRDs and Helm chart | `packages/kubernetes-controller/`                                              | [MIT](LICENSE-MIT)       |
| Pulumi provider                            | `packages/pulumi-provider/`                                                    | [MIT](LICENSE-MIT)       |
| CDK deployment integration                 | `cdk/` and the generated `dist-cdk/cdk/` code                                  | [MIT](LICENSE-MIT)       |
| Public API contract                        | `openapi/`                                                                     | [MIT](LICENSE-MIT)       |

Each subtree's license applies to its source and generated code. The root
package contains both the AGPL service/console and MIT deployment code, so its
package metadata uses `AGPL-3.0-only AND MIT`. Importing `hemlig/cdk` uses the
MIT integration; the service and console it packages and deploys remain AGPL.
The MIT client, CLI, controller and Pulumi provider do not import the service's
AGPL implementation. They communicate with it through the public API.

Published packages and the Helm chart include their component license files.
The controller image includes MIT notices for the controller and client.
CDK-generated Lambda archives include the AGPL text, and console builds include
the AGPL text and the MIT client notice.

Third-party dependencies retain their own licenses and notices. This policy
does not relicense third-party software.

## Commercial hosting and source availability

Commercial use, self-hosting and selling a hosted Hemlig service are allowed.
For a modified AGPL-covered program that supports network interaction, AGPL
section 13 requires prominently offering its complete Corresponding Source to
all users interacting with it remotely, at no charge. Offering only an older
upstream version while withholding the deployed changes does not satisfy that
requirement. Distributed copies also have the AGPL's source and notice
requirements. The license text governs the exact obligations.

Operators should give service users a visible source link, such as in the
console and service documentation, identifying the exact deployed version.
Keep its complete source and build/install material available; include your
changes, preserve applicable notices, and follow the AGPL's definition of
Corresponding Source. The upstream repository is
[zyno-io/hemlig](https://github.com/zyno-io/hemlig); a modified deployment must
offer its own corresponding version. A package tarball or a link to the latest
upstream branch may not contain everything required to rebuild a deployment.

Source obligations concern the covered software. They do not require exposing
stored secret payloads, OIDC tokens, private keys, certificates or customer
data. A separate application using the MIT client or calling the HTTP API does
not become AGPL merely because it uses Hemlig. Incorporating AGPL implementation
code into another program requires assessing the combined work's obligations.

There is no restriction specifically banning SaaS, and no noncommercial-only
condition. The intended requirement is that covered downstream changes remain
available to their users under the applicable AGPL terms.

See the [AGPL text, especially sections 1, 4–6 and 13](LICENSE),
[GNU's explanation](https://www.gnu.org/licenses/why-affero-gpl.html), and
[the GNU FAQ](https://www.gnu.org/licenses/gpl-faq.en.html).

## Earlier releases and contributions

This licensing split applies to versions containing this change. Previously
released Apache-2.0 versions retain their existing permissions, including the
right to fork and commercially host those versions. This change does not
revoke the Apache grants or retroactively change deployed artifacts.

Contributions must be submitted under the license of the component they
modify. Contributors must have the rights to license their contributions;
retain any applicable third-party notices. A change to this policy does not
silently grant rights to relicense someone else's contributions.
