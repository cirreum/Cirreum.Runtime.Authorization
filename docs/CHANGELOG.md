# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Per-scheme application user resolution for multi-IdP server hosts, paired
with the `Cirreum.Core 5.0.0` rework. A Cirreum API host that fans in
across workforce + customer IdPs (and credential schemes like ApiKey /
SignedRequest / External BYOID) can now register one
`IApplicationUserResolver` per scheme; the role claims transformer's
internal adapter dispatches to the matching resolver per request based on
the authenticated scheme, rather than packing scheme-detection logic into
a single resolver or fanning out queries across user stores.

### Changed

- **`CirreumAuthorizationBuilder.AddApplicationUserResolver<TResolver>()`
  now allows multiple registrations** (one per IdP scheme). Previously
  `TryAddScoped` silently ignored a second call, leaving the first
  registration in effect. The resolver registration switched to
  `AddScoped`; the adapter + telemetry registrations remain idempotent
  via the existing marker pattern. Callers passing the same scheme twice
  will get silent first-wins behavior at dispatch time — single-resolver
  apps and multi-IdP apps both work without code change beyond declaring
  `Scheme` on the resolver.
- **`ApplicationUserRoleResolverAdapter` now dispatches by scheme.** Ctor
  changed from `IApplicationUserResolver resolver` to
  `IEnumerable<IApplicationUserResolver> resolvers`; selects the resolver
  whose `Scheme` matches the request's authenticated scheme (read from
  `AuthenticationContextKeys.AuthenticatedScheme` on `HttpContext.Items`),
  falling back to the resolver whose `Scheme` is `null`. No matching
  resolver is the correct outcome for operator/machine-track callers
  (workforce IdP, ApiKey, SignedRequest, External BYOID) — they have no
  application user record by design. Internal class — type-signature
  change is not externally visible.
- **Dynamic scheme `ForwardDefaultSelector` now stamps
  `AuthenticationContextKeys.AuthenticatedScheme`** on
  `HttpContext.Items` (replacing the removed
  `IAuthenticationBoundaryResolver.ResolvedSchemeKey` const). The string
  literal value also changed from `"__Cirreum_ResolvedAuthScheme"` to
  `"__Cirreum_AuthenticatedScheme"` to match the new const name. Any
  external code reading the dictionary by raw literal will read `null`
  post-upgrade — switch to the const.

### Fixed

- **`ApplicationUserRoleResolverAdapter` now short-circuits on a cache
  hit.** When `HttpContext.Items[AuthenticationContextKeys.ApplicationUserCache]`
  is already populated (e.g. by custom middleware, a test harness, or a
  pre-warmed context), the cached `IApplicationUser`'s roles are returned
  directly — no scheme dispatch, no resolver call. The adapter remains
  the canonical writer of the cache on miss; this read is symmetric with
  `UserAccessor`'s hot path in `Cirreum.Services.Server`.

### Updated

- **`Cirreum.Core`** — `4.0.2` → `5.0.1` (transitive major bump). Picks up
  `AuthenticationContextKeys` and `IApplicationUserResolver.Scheme`.

### Migration

**Existing single-resolver apps — no code change required.** The default
`Scheme => null` on `IApplicationUserResolver` makes the existing resolver
the universal fallback, which is identical to the prior single-resolver
behavior.

**Multi-IdP server hosts** can now register one resolver per scheme:

```csharp
public sealed class CustomerEntraResolver : IApplicationUserResolver {
    public string Scheme => "EntraExternalId";   // matches the configured scheme name
    public Task<IApplicationUser?> ResolveAsync(string externalUserId, CancellationToken ct = default) { ... }
}

public sealed class BorrowerDescopeResolver : IApplicationUserResolver {
    public string Scheme => "Descope";
    public Task<IApplicationUser?> ResolveAsync(string externalUserId, CancellationToken ct = default) { ... }
}

builder.AddAuthorization(auth => auth
    .AddApplicationUserResolver<CustomerEntraResolver>()
    .AddApplicationUserResolver<BorrowerDescopeResolver>());
```

The `Scheme` value must match the configured authentication scheme name
(the same name registered by `Cirreum.Authorization.*` registrars from
`appsettings.json` under `Cirreum:Authorization:Providers:{Type}:Instances:{Key}`).

**Operator/machine-track schemes need no resolver** — workforce IdP,
ApiKey, SignedRequest, and External BYOID callers don't have application
user records by design. The dispatcher's "no scheme match, no null-Scheme
fallback" path returns `null` cleanly, and the grant evaluator's
documented null-fall-through accommodates the absence of an
`IApplicationUser`.

**`HttpContext.Items` raw-literal readers** must switch from
`"__Cirreum_ResolvedAuthScheme"` to either
`AuthenticationContextKeys.AuthenticatedScheme` (preferred) or the new
literal `"__Cirreum_AuthenticatedScheme"`. The forward selector and the
role claims transformer (in `Cirreum.Runtime.AuthorizationProvider`) both
write the new value.
