---
title: Microsoft Entra ID recipe
description: Use one Entra app registration as the API and the console client, with app roles for administrators.
pageType: how-to
---

# Microsoft Entra ID recipe

Use one Entra app registration as both the API and the console's single-page client, so the client ID appears once.

**Before you start:** you need rights to edit app registrations and enterprise applications in the tenant, and the [guide](../identity-provider.md) open for the field meanings. About 20 minutes.

## Set up the app

1. In the app registration, expose the `hemlig.admin` scope and keep the default Application ID URI `api://<client ID>`; the derived console scope depends on it.
2. Set the access token version to 2 in the manifest: `api.requestedAccessTokenVersion: 2` in the Microsoft Graph manifest, or `accessTokenAcceptedVersion: 2` in the legacy AAD Graph manifest. A v1 token has a different issuer and an `api://` audience, and fails at the gateway.
3. Grant consent: API permissions, Add a permission, My APIs, this app, `hemlig.admin`, then **Grant admin consent**. Include the Microsoft Graph delegated `openid`, `profile` and `email`, which the console also requests. Without consent the first sign-in can fail with AADSTS65001.
4. Under Authentication, add the **Single-page application** platform and the three console redirect URIs from [Redirect URIs, CORS and CSP](../identity-provider.md#redirect-uris-cors-and-csp). Leave the implicit grant boxes off. The Web platform fails the browser's token redemption.
5. Define an app role, for example `Hemlig.Administrator`, allowed for users. Assign it to the administrators or, preferably, to a group.
6. On the matching enterprise application (Enterprise applications, Properties), set **Assignment required** to Yes and assign only the people who should reach Hemlig. Without it, any user in the tenant can obtain a token for the app.

## Token shape

| Claim | Value |
| --- | --- |
| `iss` | The tenant's v2 issuer, ending in `/v2.0` |
| `aud` | The app's bare client ID (v2 tokens), never the `api://` URI |
| `scp` | `hemlig.admin`, a space-delimited string |
| `roles` | An array of app role values |
| `oid` | A stable object ID for the person. Use it as the subject |

A browser requests the resource-qualified scope `api://<client ID>/hemlig.admin`; the token carries only the short name. A bare `hemlig.admin` is read as a Microsoft Graph scope, which is why the console scope is derived.

## Hemlig config

```json
{
  "context": {
    "oidcIssuer": "https://login.microsoftonline.com/TENANT_ID/v2.0",
    "oidcClientId": "00000000-0000-0000-0000-000000000000",
    "oidcAdminScope": "hemlig.admin",
    "oidcSubjectClaim": "oid",
    "oidcAdminRole": "Hemlig.Administrator"
  }
}
```

From these, `oidcAudience` defaults to the client ID and `oidcConsoleAccessScope` defaults to `api://<client ID>/hemlig.admin`. The scope default applies to the issuer hosts `login.microsoftonline.com`, `login.microsoftonline.us` and `login.chinacloudapi.cn`. For any other host, set `oidcConsoleAccessScope` yourself.

`oidcRoleClaim` stays unset, so the Lambda reads `roles`. Leave `oidcAuthorizeParams` and `oidcProviderOrigins` unset: the issuer origin covers the token endpoint.

::: details Advanced: split apps or custom identifier URIs
Keep two registrations, or a custom identifier URI, by setting the explicit fields. An explicit value always wins over the default.

```json
{
  "context": {
    "oidcAudience": "API_APP_ID",
    "oidcConsoleAccessScope": "api://API_APP_ID/hemlig.admin",
    "oidcClientId": "CONSOLE_APP_ID"
  }
}
```
:::

## Caveats

- **Subject:** `oid` is the same for a person across apps in the tenant. `sub` is pairwise per application, so it can change if you move to another client. Use `oid`.
- **Groups:** do not read the `groups` claim. Past the size limit Entra replaces it with `_claim_names`, and the Lambda refuses with `role_overage`. Use app roles.
- **App roles on groups:** assigning an app role to a group needs a paid Entra ID tier (P1 or higher). Without it, assign the role to users.
- **Self-consent:** whether an app can pre-authorize itself instead of using an API permission plus admin consent: verify in your tenant.
- **Post-logout URI:** whether it must also appear in the redirect list: verify in your tenant. Copy the console origin to both if sign-out reports a redirect error.

## Next steps

- [Verify your token](../identity-provider.md#verify-your-token)
- [Troubleshoot sign-in and authorization](../identity-provider.md#troubleshoot-sign-in-and-authorization)
- [Host the console](../console.md)
