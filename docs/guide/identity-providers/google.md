---
title: Google recipe
description: Sign in to the console with Google accounts through a broker, because Google cannot serve Hemlig directly.
pageType: how-to
---

# Google recipe

Use Google Workspace or Google accounts as the upstream identity, and put a broker in front of them for Hemlig.

**Before you start:** pick a broker and finish its recipe first. About 15 minutes on top of it.

## Why Google cannot sign in to the console directly

The console is a public single-page client with no secret. Google does not fit that model for two reasons:

- Google issues no JWT access tokens for custom APIs. Its access tokens are opaque, so the gateway cannot validate them, and only ID tokens are signed JWTs. With the console, Hemlig accepts only access tokens: the `oidcAdminScope` check rejects ID tokens.
- A Google "Web application" client appears to require a client secret at the token endpoint even with PKCE, which a browser app cannot hold. Verify in your tenant.

So direct console sign-in with Google is not supported. Do not put a Google client secret in `config.json`.

## Use a broker

Put a provider that can federate Google in front of Hemlig. It issues the JWT access tokens, scope and roles, and Google only authenticates the person.

| Broker | Federates Google | Start from |
| --- | --- | --- |
| Keycloak | Yes, as an identity provider | [Keycloak recipe](keycloak.md) |
| Auth0 | Yes, as a social connection | [Auth0 recipe](auth0.md) |
| Okta | Yes, as an identity provider | [Okta recipe](okta.md) |
| Zitadel, Authentik | Yes, as an external login source | [Other providers](others.md) |
| Dex | Yes, as a connector | Verify in your tenant that your Dex version issues JWT access tokens with `aud` and a scope. This page does not document it |

In each case, add Google as the upstream, then follow the broker's recipe for the app, audience, scope and role claim. Restrict who can sign in at the broker, for example by Workspace domain, and map a group or attribute to the administrator role there.

## API-only automation with a service account

For automation without the console, a Google service account can mint an ID token for your audience. This works only as an API-only deployment: no `consoleFqdn`, no `oidcAdminScope`, and an explicit `oidcAudience` that is not the client ID.

`oidcAdminRole` is mandatory here. Any Google service account in any project can mint a token for any audience, so the audience is not a gate and the role list is the only one.

```sh
gcloud auth print-identity-token --audiences=hemlig-api
```

The token has `iss` for Google, `aud` set to your audience and `sub` set to the service account's unique ID. Match the role against `sub`:

```json
{
  "context": {
    "oidcIssuer": "https://accounts.google.com",
    "oidcAudience": "hemlig-api",
    "oidcSubjectClaim": "sub",
    "oidcRoleClaim": "sub",
    "oidcAdminRole": "SERVICE_ACCOUNT_UNIQUE_ID"
  }
}
```

Caveats:

- Google's ID-token `iss` can appear with or without the `https://` scheme. The gateway and Lambda compare it exactly, so decode a real token and match it. Verify in your tenant.
- This path has no scope check. List only service account IDs you control.
- Whether the gateway accepts Google's tokens with your issuer string: verify in your tenant.

## Caveats

- **Sign-out:** Google's discovery has no `end_session_endpoint`. If you sign in to the broker with Google, sign-out behaviour follows the broker.
- **Silent renew:** whether `accounts.google.com` can be framed for silent renewal: verify in your tenant. Brokers are not affected.

## Next steps

- [Troubleshoot sign-in and authorization](../identity-provider.md#troubleshoot-sign-in-and-authorization)
- [Keycloak recipe](keycloak.md)
- [Host the console](../console.md)
