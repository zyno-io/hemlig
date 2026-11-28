# Test-only OIDC realm

`keycloak-realm.json` is a **test-only** Keycloak realm for the OIDC integration
check (`src/scripts/verify-oidc.ts`, CI job `oidc-keycloak`). Every credential in
it is a throwaway value that protects nothing. Never import it into a real
Keycloak.

Keycloak's realm importer rejects unknown fields, so notes like this one live
here rather than as `_comment` keys in the JSON.
