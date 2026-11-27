---
title: Connect your identity provider
description: Configure the OIDC token requirements for the administrator API and verify a token with curl.
pageType: how-to
---

# Connect your identity provider

Configure your OIDC provider so its access tokens satisfy the administrator API, then verify a real token with curl before you rely on it.

Hemlig does not create users, app registrations or administrator groups. Your provider must expose an HTTPS OIDC issuer with a JWKS and issue RSA-signed JWTs.

**Before you start:** you need admin rights in your provider and the [CDK config](deploying.md#_3-fill-in-the-oidc-values) fields in front of you. About 15 minutes.

## What the API checks

Every administrator request is checked twice: by API Gateway, then again by the admin Lambda. A token must be an access token, not an ID token.

With separate API and console apps the audience check rejects an ID token. In a one-app setup an Entra ID token has `aud` equal to the client ID, so the audience check passes; the `oidcAdminScope` (`scp`) check is what rejects it, because ID tokens carry no `scp`. For that reason `oidcAdminScope` is required whenever `oidcAudience` is omitted.

| Requirement | Config field | Checked by | Token claim |
| --- | --- | --- | --- |
| Issuer matches exactly | `oidcIssuer` | Gateway and Lambda | `iss` |
| Audience matches (any of a list) | `oidcAudience` | Gateway and Lambda | `aud` (or `client_id` when `aud` is absent) |
| Signature and expiry | none | Gateway | n/a |
| Administrator scope | `oidcAdminScope` | Gateway and Lambda, when set | `scope` or `scp` |
| Administrator role (any of a list) | `oidcAdminRole` | Lambda, when set | the claim named by `oidcRoleClaim`, else `roles` or `role` |
| Stable identity | `oidcSubjectClaim` (default `sub`) | Lambda | the configured claim must be present |

The scope and role are optional for API-only use, but `oidcAdminScope` is **required** when you enable the [console](console.md). A scope is one token, not a list.

Where the role lives is provider-specific. `oidcRoleClaim` names a top-level claim, or an RFC 6901 JSON Pointer such as `/realm_access/roles`. Leave it unset for the `roles`/`role` default.

Role values may contain spaces (`Hemlig Admins`) but not commas. `oidcRoleClaim` requires `oidcAdminRole`. A console without `oidcAdminRole` makes synthesis warn that any holder of the admin scope is an administrator.

Two console-only fields cover providers that differ from the Entra shape:

- `oidcAuthorizeParams` adds authorize query parameters, such as Auth0's `audience`.
- `oidcProviderOrigins` adds CSP origins when the token endpoint is on another origin.

When discovery has no `end_session_endpoint` (Cognito, Google, Dex), sign-out clears the console session and returns to the console origin. Per-provider recipes follow in a later revision.

`oidcSubjectClaim` is recorded as the owner of every change and drives idempotency. Pick a claim that never changes for a person.

::: tip Scope on automation tokens
When `oidcAdminScope` is set, every administrator token must carry it, including tokens for automation. Some providers put machine-to-machine grants in a `roles` claim and no scope. For those, leave `oidcAdminScope` unset and restrict access with `oidcAdminRole`.
:::

## Provider notes

Replace the placeholder hosts, tenant and application IDs with your own.

::: code-group

```text [Entra]
oidcIssuer   https://login.microsoftonline.com/TENANT_ID/v2.0
oidcClientId    the one app registration's (client) ID; also the audience
oidcAdminScope  hemlig.admin   (short name, as carried in scp)
oidcAdminRole   app role value, carried in roles
                (oidcAudience and oidcConsoleAccessScope are derived; see below)
```

```text [Okta]
oidcIssuer   https://example.okta.com/oauth2/AUTH_SERVER_ID
oidcAudience the custom authorization server's Audience
oidcAdminScope  a custom scope on that server, carried in scp
oidcAdminRole   a custom claim named roles (optional)
```

```text [Auth0]
oidcIssuer   https://example.auth0.com/   (the trailing slash is part of it)
oidcAudience the API Identifier
oidcAdminScope  a permission on that API, carried in scope
oidcAdminRole   leave unset
```

```text [Keycloak]
oidcIssuer   https://login.example.com/realms/REALM
oidcAudience add an Audience mapper; the default aud is account
oidcAdminScope  a client scope carried in scope
oidcAdminRole   a mapper that emits a multivalued claim named roles
```

:::

Points that commonly go wrong:

- **Entra** is simplest as one app registration: the API app is also the console's single-page client. See [One app on Entra](#one-app-on-entra). It must issue v2 tokens: set `accessTokenAcceptedVersion` to `2` in the API app's manifest. A v1 token has a different issuer and an `api://` audience, and fails at the gateway. A browser requests the resource-qualified scope; the token carries only the short name.
- **Okta** needs a custom authorization server. Org-server tokens are not meant for your own API.
- **Auth0** normally ignores custom claims without a namespaced name, so it cannot emit the plain `roles` claim Hemlig reads. Use the scope instead.
- **Keycloak** puts realm roles in a nested `realm_access.roles` claim. Add a mapper to emit a top-level `roles` claim.

### One app on Entra

Use one app registration as both the API and the console client, so the client ID appears once.

1. In the app registration, expose the `hemlig.admin` scope and keep the default Application ID URI `api://<client ID>`; the derived console scope depends on it. Set the access token version to 2 in the manifest: `api.requestedAccessTokenVersion: 2` in the Microsoft Graph manifest, or `accessTokenAcceptedVersion: 2` in the legacy AAD Graph manifest.
   Then grant consent: API permissions, Add a permission, My APIs, this app, `hemlig.admin`, then **Grant admin consent** (include `openid`, `profile` and `email`, which the console also requests). Without it the first sign-in can fail with AADSTS65001.
2. On the same registration, add the **Single-page application** platform and the console redirect URIs listed under [Console client registration](#console-client-registration).
3. On the matching enterprise application (Enterprise applications, Properties), set **Assignment required** to Yes and assign only the administrators and groups that should reach Hemlig. Without it, any user in the tenant can obtain a token for the app.
4. Deploy with the client ID once, as in the block below.

```text
oidcIssuer      https://login.microsoftonline.com/TENANT_ID/v2.0
oidcClientId    APP_ID
oidcAdminScope  hemlig.admin
oidcSubjectClaim  oid
oidcAdminRole   Hemlig.Administrator
```

From these, `oidcAudience` defaults to `APP_ID` and `oidcConsoleAccessScope` defaults to `api://APP_ID/hemlig.admin`. The scope default applies to the issuer hosts `login.microsoftonline.com`, `login.microsoftonline.us` and `login.chinacloudapi.cn`. For any other issuer the default is `oidcAdminScope` as-is.

::: details Advanced: split apps or custom identifier URIs
Keep two registrations, or a custom identifier URI, by setting the explicit fields. An explicit value always wins over the default.

```text
oidcAudience            API_APP_ID
oidcConsoleAccessScope  api://API_APP_ID/hemlig.admin
oidcClientId            CONSOLE_APP_ID
```
:::

### Console client registration

The console is a browser app using the authorization-code flow with PKCE. Register it as a single-page application and allow these redirect URIs for your `consoleFqdn`.

| Purpose | URI |
| --- | --- |
| Sign-in callback | `https://console.example.com/auth/callback` |
| Silent token renewal | `https://console.example.com/silent.html` |
| Post-logout | `https://console.example.com` |

These three are the only redirect URIs the console needs. The CLI sign-in (`hemlig login`) reuses the console's session through its `/cli-login` page, either POSTing to a `127.0.0.1` listener or showing a copy code, so it registers no redirect URI with your provider. The client ID becomes `oidcClientId`. The console also requests `openid`, `profile` and `email`; `email` is display-only.

## Verify your token

Obtain an access token with your provider's normal tooling, then check it in two steps. Do not paste production tokens into third-party decoders.

1. Decode the claims locally.

   ```sh
   export TOKEN=paste-an-access-token-here
   python3 -I -c "import base64,json,sys;p=sys.argv[1].split('.')[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))),indent=1))" "$TOKEN"
   ```

   Expected output is a JSON object. Compare it with your config:

   | Claim | Must equal |
   | --- | --- |
   | `iss` | `oidcIssuer`, character for character (watch trailing slashes and `/v2.0`) |
   | `aud` | `oidcAudience`. A client ID that is not the audience, or an ID token, means you asked for the wrong thing |
   | `scp` or `scope` | contains `oidcAdminScope`, when configured |
   | `roles` or `role` | contains `oidcAdminRole`, when configured |
   | your `oidcSubjectClaim` | is present |

2. Call the API.

   ```sh
   export HEMLIG_ADMIN_URL=https://admin.example.com
   curl -sS -o /dev/null -w '%{http_code}\n' \
     "$HEMLIG_ADMIN_URL/v1/admin/environments" \
     -H "authorization: Bearer $TOKEN"
   ```

   Expected output:

   ```text
   200
   ```

| Status | Meaning | Fix |
| --- | --- | --- |
| `401` | API Gateway rejected the token before Lambda | Missing or invalid token, audience, issuer, signature or expiry. Get a new token |
| `403` | Insufficient scope (API Gateway), or the Lambda refused the token | Request the required scope. If the scope is present, the gateway and Lambda disagree on issuer, audience, scope or role: fix the config |

## Next steps

- [Deploy Hemlig to AWS](deploying.md)
- [Host the console](console.md)
- [Configuration reference](../reference/configuration.md)
