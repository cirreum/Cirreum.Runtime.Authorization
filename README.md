# Cirreum.Runtime.Authorization

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Runtime.Authorization.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authorization/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Runtime.Authorization.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authorization/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Runtime.Authorization?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Runtime.Authorization/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Runtime.Authorization?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Runtime.Authorization/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Unified authentication and authorization for ASP.NET Core applications**

## Overview

**Cirreum.Runtime.Authorization** is the composition layer that unifies all Cirreum authorization providers into a single, coherent system. It provides dynamic scheme selection, conflict detection, and predefined role-based policies.

### Key Features

- **Dynamic scheme selection** - Automatically routes to the correct authentication handler based on request characteristics
- **Fail-closed design** - Rejects requests that don't match any configured provider
- **Conflict detection** - Rejects ambiguous requests with multiple authentication indicators
- **Multi-provider support** - Entra, API Key, Signed Request, and External (BYOID)
- **Cross-scheme policies** - Role-based authorization that works across all authentication types
- **Predefined policies** - Hierarchical role-based policies for common scenarios

### Supported Providers

| Provider | Package | Use Case |
|----------|---------|----------|
| **Entra** | `Cirreum.Authorization.Entra` | Azure AD / Entra ID JWT tokens |
| **API Key** | `Cirreum.Authorization.ApiKey` | Static and dynamic API key authentication |
| **Signed Request** | `Cirreum.Authorization.SignedRequest` | HMAC-signed requests for partners |
| **External (BYOID)** | `Cirreum.Authorization.External` | Multi-tenant customer IdP tokens |

## Installation

```bash
dotnet add package Cirreum.Runtime.Authorization
```

## How It Works

### Authorization Flow

```
Request arrives
    │
    ▼
Routing determines endpoint
    │
    ▼
Endpoint has [Authorize] or .RequireAuthorization()?
    │
    ├── NO  → Request proceeds (no authentication)
    │
    └── YES → Policy evaluated
                 │
                 ▼
              Policy specifies scheme?
                 │
                 ├── YES → Use that scheme directly
                 │
                 └── NO  → ForwardDefaultSelector routes dynamically
                              │
                              ▼
                           Scheme handler authenticates
                              │
                              ▼
                           Policy requirements checked (roles, claims)
```

**Important:** Authentication only occurs when an endpoint requires authorization. Anonymous endpoints never trigger scheme selection.

### Dynamic Scheme Selection

The `ForwardDefaultSelector` examines request characteristics and routes to the appropriate handler:

```
1. Conflict check     → Ambiguous indicators? → Reject (401)
2. API Key header     → X-Api-Key present?    → API Key handler
3. Signed Request     → All 3 headers?        → Signed Request handler
4. External (BYOID)   → Tenant + Bearer?      → External handler
5. JWT Bearer         → Bearer token?         → Entra handler (by audience)
6. No match           → Nothing matched       → Reject (401)
```

**Note:** There is no silent fallback. If the selector cannot determine the appropriate scheme, the request is rejected. This fail-closed behavior prevents credentials from being evaluated by an unrelated handler.

### Conflict Detection

When a request contains conflicting authentication indicators, it's rejected rather than guessing:

```
❌ X-Api-Key + X-Tenant-Slug → Ambiguous (401)
✓  X-Api-Key only           → API Key handler
✓  X-Tenant-Slug + Bearer   → External handler
```

This prevents "scheme shopping" attacks where an attacker sends multiple credentials hoping one works.

## Usage

### Basic Setup

```csharp
var builder = WebApplication.CreateBuilder(args);

// Registers all configured providers from appsettings.json
builder.AddAuthorization();
```

The authentication and authorization middleware is automatically configured by the Cirreum runtime - no need to call `UseAuthentication()` or `UseAuthorization()` manually.

### Builder Pattern

The `AddAuthorization` method accepts an optional lambda for configuring additional authentication schemes via `CirreumAuthorizationBuilder`:

```csharp
builder.AddAuthorization(auth => auth
    .AddSignedRequest<TResolver>()      // HMAC-signed requests
    .AddDynamicApiKeys<TResolver>([])   // Database-backed API keys
    .AddExternal<TResolver>()           // Multi-tenant BYOID
)
.AddPolicy("MyPolicy", policy => ...);  // Standard ASP.NET Core policies
```

This pattern:
- Keeps Cirreum-specific configuration grouped together
- Returns the standard `AuthorizationBuilder` for chaining policies
- Prevents accidental use without first calling `AddAuthorization()`

### With External (BYOID) Authentication

```csharp
builder.AddAuthorization(auth => auth
    .AddExternal<DatabaseTenantResolver>()
)
.AddPolicy("TenantAccess", policy => {
    policy
        .AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("app:user");
});
```

### With Dynamic API Keys

```csharp
builder.AddAuthorization(auth => auth
    .AddDynamicApiKeys<DatabaseApiKeyResolver>(
        headers: ["X-Api-Key"],
        options => options.WithCaching())
);
```

### With Signed Request Authentication

```csharp
builder.AddAuthorization(auth => auth
    .AddSignedRequest<DatabaseSignedRequestResolver>()
    .AddSignatureValidationEvents<RateLimitingEvents>()
);
```

### Combined Setup (All Providers)

```csharp
builder.AddAuthorization(auth => auth
    // External (BYOID) for customer IdPs
    .AddExternal<DatabaseTenantResolver>()
    // Dynamic API keys for internal services
    .AddDynamicApiKeys<DatabaseApiKeyResolver>(
        headers: ["X-Api-Key"],
        options => options.WithCaching())
    // Signed requests for external partners
    .AddSignedRequest<DatabaseSignedRequestResolver>()
    .AddSignatureValidationEvents<RateLimitingEvents>()
)
// Custom policies via standard ASP.NET Core AuthorizationBuilder
.AddPolicy("TenantAccess", policy => {
    policy
        .AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("tenant:user");
})
.AddPolicy("PartnerAccess", policy => {
    policy
        .AddAuthenticationSchemes(SignedRequestDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("partner");
});
```

## Configuration

### appsettings.json

```json
{
  "Cirreum": {
    "Authorization": {
      "PrimaryScheme": "WorkforceUsers",
      "Providers": {
        "Entra": {
          "Instances": {
            "WorkforceUsers": {
              "Enabled": true,
              "Audience": "api://your-app-id",
              "TenantId": "your-tenant-id"
            }
          }
        },
        "ApiKey": {
          "Instances": {
            "InternalService": {
              "Enabled": true,
              "HeaderName": "X-Api-Key",
              "ClientId": "internal-svc",
              "Roles": ["App.System"]
            }
          }
        },
        "External": {
          "Instances": {
            "default": {
              "Enabled": true,
              "TenantIdentifierSource": "Header",
              "TenantHeaderName": "X-Tenant-Slug",
              "RequireHttpsMetadata": true
            }
          }
        }
      }
    }
  }
}
```

### Configuration Reference

| Setting | Required | Description |
|---------|----------|-------------|
| `PrimaryScheme` | Yes | The Entra instance name used exclusively for the `System` policy. Must match one of your configured Entra instance names. |
| `Providers` | Yes | Provider configurations (Entra, ApiKey, External, etc.) |

**Important:** `PrimaryScheme` is used **only** for the `System` authorization policy. It is **not** a fallback for unmatched requests. If the dynamic selector cannot determine a scheme, the request is rejected.

## Authorization Policies

### Predefined Policies

The library includes hierarchical role-based policies:

| Policy | Scheme | Roles | Description |
|--------|--------|-------|-------------|
| `System` | Primary only | `App.System` | Highest privilege, restricted to primary Entra instance |
| `StandardAdmin` | Dynamic | `App.System`, `App.Admin` | Administrative access |
| `StandardManager` | Dynamic | + `App.Manager` | Management access |
| `StandardAgent` | Dynamic | + `App.Agent` | Agent/service access |
| `StandardInternal` | Dynamic | + `App.Internal` | Internal user access |
| `Standard` | Dynamic | + `App.User` | All authenticated users |

The `System` policy is special - it **only** accepts authentication from the primary Entra instance (configured via `PrimaryScheme`). This ensures system-level operations cannot be performed via API keys or other mechanisms.

All other policies use the dynamic scheme, allowing authentication via any configured provider.

### Cross-Scheme Authorization

Policies using the dynamic scheme work across all authentication types. The `auth_scheme` claim identifies which handler authenticated the request.

```csharp
// Accept ANY configured authentication method
// The dynamic scheme routes to the appropriate handler based on request indicators
builder.AddAuthorization()
    .AddPolicy("PartnerAccess", policy => {
        policy
            .AddAuthenticationSchemes(AuthorizationSchemes.Dynamic)
            .RequireAuthenticatedUser()
            .RequireRole("partner");
    });
```

### Scheme-Specific Authorization

To restrict a policy to a specific authentication method, use that scheme directly:

```csharp
// Only accept External (BYOID) authentication
builder.AddAuthorization()
    .AddPolicy("TenantOnly", policy => {
        policy
            .AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireRole("tenant:user");
    });

// Only accept API key authentication
builder.AddAuthorization()
    .AddPolicy("ServiceOnly", policy => {
        policy
            .AddAuthenticationSchemes("Header:X-Api-Key")
            .RequireAuthenticatedUser()
            .RequireRole("App.System");
    });

// Only accept Signed Request authentication
builder.AddAuthorization()
    .AddPolicy("PartnerOnly", policy => {
        policy
            .AddAuthenticationSchemes(SignedRequestDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser()
            .RequireRole("partner");
    });
```

### Available Scheme Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `AuthorizationSchemes.Dynamic` | `DynamicScheme` | Routes to appropriate handler based on request |
| `ExternalDefaults.AuthenticationScheme` | `byoid` | External (BYOID) authentication only |
| `SignedRequestDefaults.AuthenticationScheme` | `SignedRequest` | Signed request authentication only |
| `"Header:{HeaderName}"` | e.g., `Header:X-Api-Key` | API key authentication for specific header |

## Scheme Selection Reference

| Request Indicators | Selected Scheme |
|--------------------|-----------------|
| `X-Api-Key` + `X-Tenant-Slug` (header) | **Rejected** (ambiguous) |
| `X-Api-Key` | API Key handler |
| `X-Client-Id` + `X-Timestamp` + `X-Signature` | Signed Request handler |
| `X-Tenant-Slug` + `Authorization: Bearer` | External (BYOID) handler |
| `Authorization: Bearer` (recognized audience) | Entra handler |
| `Authorization: Bearer` (unrecognized audience) | **Rejected** (no match) |
| No credentials | **Rejected** (no match) |

## Security Considerations

### Fail-Closed Design

The dynamic selector **never** silently falls back to an unrelated scheme:

- **Unrecognized JWT audience** → Rejected (not sent to random Entra instance)
- **No matching credentials** → Rejected (not sent to "default" scheme)
- **Conflicting indicators** → Rejected (not guessed)

This prevents credential confusion attacks where tokens or keys might accidentally be validated by the wrong handler.

### Authentication vs Authorization

- **Authentication** (who are you?) - Only triggered when an endpoint requires authorization
- **Authorization** (what can you do?) - Policy requirements checked after authentication

Anonymous endpoints (`[AllowAnonymous]`) bypass the entire authentication system.

### Scheme Priority

The selection order matters for security:

1. **Conflict detection first** - Prevents ambiguous requests from authenticating
2. **Most specific matches** - API key headers checked before generic Bearer tokens
3. **Audience matching** - JWT tokens routed by audience claim
4. **Rejection last** - No match means rejection, not fallback

### Role Normalization

All providers normalize roles to a common format, enabling cross-scheme policies. The `auth_scheme` claim lets you distinguish authentication methods when needed.

## Documentation

- **[Authentication Architecture](docs/AUTHENTICATION-ARCHITECTURE.md)** - Comprehensive security guide covering OAuth/OIDC vs Signed Request trade-offs, partner security considerations, and RFC compliance

## Contribution Guidelines

1. **Be conservative with new abstractions** - The API surface must remain stable
2. **Limit dependency expansion** - Only foundational, version-stable dependencies
3. **Favor additive, non-breaking changes** - Breaking changes ripple through the ecosystem
4. **Include thorough unit tests** - All patterns should be independently testable
5. **Document architectural decisions** - Context and reasoning for future maintainers

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
