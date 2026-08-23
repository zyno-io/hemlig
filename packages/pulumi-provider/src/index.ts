import { randomUUID } from "node:crypto";
import * as pulumi from "@pulumi/pulumi";
import {
  HemligClient,
  HemligError,
  type Grant,
  type SecretMetadata,
  type SecretPayload,
} from "@hemlig/client";
import { NodeHttpsTransport } from "@hemlig/client/node";

export interface HemligProviderArgs {
  /** Admin custom-domain URL, for example https://admin.example.com. */
  readonly adminUrl: pulumi.Input<string>;
  /** JWT/OAuth access token. Pass a Pulumi secret value. */
  readonly adminToken: pulumi.Input<string>;
}

export class Provider extends pulumi.ComponentResource {
  private readonly adminUrl: pulumi.Output<string>;
  private readonly adminToken: pulumi.Output<string>;

  public constructor(name: string, args: HemligProviderArgs, opts?: pulumi.ComponentResourceOptions) {
    super("hemlig:index:Provider", name, {}, opts);
    this.adminUrl = pulumi.output(args.adminUrl);
    this.adminToken = pulumi.secret(args.adminToken);
    this.registerOutputs({});
  }

  public secret(
    name: string,
    args: HemligSecretArgs,
    opts?: pulumi.CustomResourceOptions,
  ): HemligSecret {
    return new HemligSecret(name, args, this.adminUrl, this.adminToken, opts);
  }
}

export interface HemligSecretArgs {
  readonly secretId: pulumi.Input<string>;
  readonly environment: pulumi.Input<string>;
  readonly metadata: pulumi.Input<SecretMetadata>;
  readonly acl: pulumi.Input<readonly Grant[]>;
  /** Store as `pulumi.secret(...)`; plaintext appears in encrypted Pulumi state. */
  readonly payload: pulumi.Input<SecretPayload>;
}

interface ResolvedSecretInputs {
  readonly adminUrl: string;
  readonly adminToken: string;
  readonly secretId: string;
  readonly environment: string;
  readonly metadata: SecretMetadata;
  readonly acl: readonly Grant[];
  readonly payload: SecretPayload;
}

class HemligSecretProvider implements pulumi.dynamic.ResourceProvider {
  public async create(inputs: ResolvedSecretInputs): Promise<pulumi.dynamic.CreateResult> {
    const client = clientFor(inputs);
    let control;
    try {
      control = await client.createAdminSecret(inputs.adminToken, {
        secretId: inputs.secretId,
        environment: inputs.environment,
        metadata: inputs.metadata,
        acl: inputs.acl,
      }, randomUUID());
    } catch (error) {
      if (!(error instanceof HemligError) || error.status !== 409) {
        throw error;
      }
      control = await client.getAdminSecret(inputs.adminToken, inputs.secretId);
    }
    if (control.environment !== inputs.environment) {
      throw new Error("The existing Hemlig secret belongs to a different environment.");
    }
    if (
      JSON.stringify(control.metadata) !== JSON.stringify(inputs.metadata) ||
      JSON.stringify(control.acl ?? []) !== JSON.stringify(inputs.acl)
    ) {
      control = await client.updateAdminSecret(
        inputs.adminToken,
        inputs.secretId,
        control.controlVersionId,
        { metadata: inputs.metadata, acl: inputs.acl },
        randomUUID(),
      );
    }
    const written = await client.putAdminPayload(
      inputs.adminToken,
      inputs.secretId,
      control.controlVersionId,
      inputs.payload,
      randomUUID(),
    );
    return {
      id: inputs.secretId,
      outs: withVersions(inputs, written.controlVersionId, written.payloadVersionId),
    };
  }

  public async diff(
    _id: string,
    olds: ResolvedSecretInputs,
    news: ResolvedSecretInputs,
  ): Promise<pulumi.dynamic.DiffResult> {
    const changes = JSON.stringify(stripVersions(olds)) !== JSON.stringify(stripVersions(news));
    return { changes, replaces: olds.secretId === news.secretId ? [] : ["secretId"] };
  }

  public async update(
    _id: string,
    olds: ResolvedSecretInputs,
    news: ResolvedSecretInputs,
  ): Promise<pulumi.dynamic.UpdateResult> {
    const client = clientFor(news);
    const current = await client.getAdminSecret(news.adminToken, news.secretId);
    if (current.environment !== news.environment) {
      throw new Error("The existing Hemlig secret belongs to a different environment.");
    }
    let control = current;
    if (
      JSON.stringify(current.metadata) !== JSON.stringify(news.metadata) ||
      JSON.stringify(current.acl ?? []) !== JSON.stringify(news.acl)
    ) {
      control = await client.updateAdminSecret(
        news.adminToken,
        news.secretId,
        current.controlVersionId,
        { metadata: news.metadata, acl: news.acl },
        randomUUID(),
      );
    }
    const written = await client.putAdminPayload(
      news.adminToken,
      news.secretId,
      control.controlVersionId,
      news.payload,
      randomUUID(),
    );
    return { outs: withVersions(news, written.controlVersionId, written.payloadVersionId) };
  }

  /** Hemlig intentionally has no delete endpoint; dropping Pulumi state retains the secret. */
  public async delete(): Promise<void> {}
}

export class HemligSecret extends pulumi.dynamic.Resource {
  public readonly controlVersionId!: pulumi.Output<string>;
  public readonly payloadVersionId!: pulumi.Output<string>;

  public constructor(
    name: string,
    args: HemligSecretArgs,
    adminUrl: pulumi.Input<string>,
    adminToken: pulumi.Input<string>,
    opts?: pulumi.CustomResourceOptions,
  ) {
    super(
      new HemligSecretProvider(),
      name,
      {
        ...args,
        adminUrl,
        adminToken: pulumi.secret(adminToken),
      },
      {
        ...opts,
        additionalSecretOutputs: ["payload", "adminToken"],
      },
    );
  }
}

const clientFor = (inputs: ResolvedSecretInputs): HemligClient =>
  new HemligClient(new URL(inputs.adminUrl), new NodeHttpsTransport());

const withVersions = (
  inputs: ResolvedSecretInputs,
  controlVersionId: string,
  payloadVersionId: string | undefined,
): Record<string, unknown> => ({ ...inputs, controlVersionId, payloadVersionId });

const stripVersions = (
  value: ResolvedSecretInputs,
): ResolvedSecretInputs => {
  const withVersions = value as ResolvedSecretInputs & {
    readonly controlVersionId?: string;
    readonly payloadVersionId?: string;
  };
  const { controlVersionId: _controlVersionId, payloadVersionId: _payloadVersionId, ...inputs } = withVersions;
  return inputs;
};
