# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is **Cirreum.Runtime.Authorization**, a .NET 10 library that provides unified authentication and authorization for ASP.NET Core applications. It is the **composition layer** that wires together all Cirreum authorization providers into a single dynamic scheme selection system with hierarchical role-based policies.

## Architecture

### Core Components

- **HostingExtensions** (`Extensions/Hosting/`) — `AddAuthorization()` extension methods that register providers, configure dynamic scheme selection, and define policies
- **CirreumAuthorizationBuilder** — Fluent builder for registering dynamic authentication schemes: `AddRoleResolver<T>()`, `AddSignedRequest<T>()`, `AddDynamicApiKeys<T>()`, `AddExternalProvider<T>()`
- **AuthorizationSchemes** — Static scheme name constants: `Dynamic`, `Ambiguous`, `Anonymous`
- **AmbiguousRequestAuthenticationHandler** — Rejects requests with conflicting/unrecognized credentials (fail-closed)
- **AnonymousAuthenticationHandler** — Returns `NoResult()` for requests with no credentials

### Project Structure

```
src/Cirreum.Runtime.Authorization/
├── Extensions/
│   └── Hosting/
│       └── HostingExtensions.cs              # Provider registration + scheme selection + policies
├── AmbiguousRequestAuthenticationHandler.cs  # Fail-closed rejection handler
├── AmbiguousRequestAuthenticationOptions.cs  # Options for ambiguous handler
├── AnonymousAuthenticationHandler.cs         # NoResult() handler for anonymous access
├── AuthorizationSchemes.cs                   # Scheme name constants
├── CirreumAuthorizationBuilder.cs            # Fluent builder (role resolver, signed request, API keys, external)
├── DynamicApiKeyOptions.cs                   # Options for dynamic API key resolution
├── ExternalOptions.cs                        # Options for External (BYOID) auth
├── SignedRequestOptions.cs                   # Options for signed request auth
└── Cirreum.Runtime.Authorization.csproj
```

### Layer Responsibilities

- **Core layer** — Contracts and registrars: `Cirreum.Authorization.Entra`, `.Oidc`, `.ApiKey`, `.SignedRequest`, `.External`, `.AuthorizationProvider`
- **Runtime layer** — Implementation: `Cirreum.Runtime.AuthorizationProvider` (claims transformer, diagnostics)
- **This package (Runtime Extensions)** — Composition: wires all providers together, dynamic scheme selection, policies, OTel subscription

### Provider Registration

Providers are registered via `RegisterAuthorizationProvider<TRegistrar, TSettings, TInstanceSettings>()`:

| Provider | Registrar | Source |
|----------|-----------|--------|
| Entra | `EntraAuthorizationRegistrar` | `Cirreum.Authorization.Entra` |
| OIDC | `OidcAuthorizationRegistrar` | `Cirreum.Authorization.Oidc` |
| API Key | `ApiKeyAuthorizationRegistrar` | `Cirreum.Authorization.ApiKey` |
| External | `ExternalAuthorizationRegistrar` | `Cirreum.Authorization.External` |

### Dynamic Scheme Selection

The `ForwardDefaultSelector` in `HostingExtensions.cs` routes requests:

1. Conflict check → `Ambiguous` (401)
2. API Key headers → `Header:{name}` scheme
3. Signed Request headers → `SignedRequest` scheme
4. External (BYOID) indicators → `Byoid` scheme
5. JWT Bearer audience → matched Entra/OIDC scheme
6. No credentials → `Anonymous` (NoResult)

### Predefined Policies

| Policy | Scheme | Roles |
|--------|--------|-------|
| `System` | Primary only | `App.System` |
| `StandardAdmin` | Dynamic | System, Admin |
| `StandardManager` | Dynamic | + Manager |
| `StandardAgent` | Dynamic | + Agent |
| `StandardInternal` | Dynamic | + Internal |
| `Standard` | Dynamic | + User |

### CirreumAuthorizationBuilder Methods

| Method | Registers |
|--------|-----------|
| `AddRoleResolver<T>()` | `IRoleResolver` + claims transformer + OTel subscription |
| `AddSignedRequest<T>()` | HMAC signature validation handler + resolver |
| `AddDynamicApiKeys<T>()` | Database-backed API key resolver (with optional caching) |
| `AddExternalProvider<T>()` | Multi-tenant BYOID tenant resolver |

## Development Commands

```bash
dotnet build
dotnet pack
dotnet clean
```

## Key Dependencies

- **Cirreum.Core** — Core framework (includes OpenTelemetry transitively)
- **Cirreum.Authorization.Entra** — Entra ID JWT provider
- **Cirreum.Authorization.Oidc** — Generic OIDC JWT provider
- **Cirreum.Authorization.ApiKey** — API key provider
- **Cirreum.Authorization.SignedRequest** — HMAC signed request provider
- **Cirreum.Authorization.External** — External (BYOID) provider
- **Cirreum.Runtime.AuthorizationProvider** — Claims transformer, diagnostics, `AddRoleEnrichment()`

## Build Configuration

- **Target Framework**: .NET 10.0
- **Root Namespace**: `Cirreum.Authorization`
- **Language Version**: Latest C#
- **Nullable**: Enabled
- **Implicit Usings**: Enabled
- **Documentation**: XML documentation file generation enabled
- **Local Release Version**: 1.0.100-rc
