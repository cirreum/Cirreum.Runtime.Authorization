# Authentication Architecture Overview

## Summary

Cirreum.Runtime.Authorization provides a unified, flexible authentication system that supports multiple identity providers simultaneously. This document outlines the available authentication methods, security design principles, and use cases for each approach.

## Authentication Providers

The system supports four authentication providers, each designed for specific use cases:

| Provider | Use Case | Token Type | Best For |
|----------|----------|------------|----------|
| **Entra ID** | Internal workforce & first-party apps | JWT Bearer | Employees, internal services |
| **External (BYOID)** | Customer/partner IdPs | JWT Bearer | B2B SaaS, multi-tenant apps |
| **API Key** | Simple service integrations | Header-based | Internal microservices, simple integrations |
| **Signed Request** | High-security M2M | HMAC signature | Financial partners, regulated industries |

## Partner Authentication Options

When onboarding external partners, you have multiple authentication strategies:

### Option 1: Entra External ID (Guest Users)

Partners are invited as guests to your Entra External ID tenant.

**Characteristics:**
- You control the identity lifecycle
- Partners use their existing Microsoft/social accounts
- Central audit logging in your tenant
- Best for: Partners who prefer federated sign-in without maintaining their own IdP

**Flow:**
```
Partner User → Your Entra External ID → Your API
```

### Option 2: External (BYOID - Bring Your Own IdP)

Partners authenticate against their own identity provider.

**Characteristics:**
- Partners maintain full control of their identities
- Zero trust model - you validate their tokens
- Supports any OIDC-compliant IdP (Okta, Auth0, Azure AD, Ping, etc.)
- Best for: Enterprise customers with existing IdP infrastructure

**Flow:**
```
Partner User → Partner's IdP → Bearer Token → Your API (validates against partner's OIDC config)
```

### Option 3: API Key Authentication

Simple header-based authentication with pre-shared keys.

**Characteristics:**
- Simplest integration path
- No token management overhead for partners
- Keys can be static (configuration) or dynamic (database-backed)
- Best for: Internal services, simple integrations, development/testing

**Flow:**
```
Partner Service → X-Api-Key Header → Your API
```

### Option 4: Signed Request Authentication

HMAC-based request signing for high-security scenarios.

**Characteristics:**
- Proves request authenticity and integrity
- Prevents replay attacks (timestamp validation)
- No bearer tokens to intercept
- Best for: Financial services, healthcare, regulatory compliance

**Flow:**
```
Partner Service → Signs request with shared secret → X-Signature + X-Timestamp + X-Client-Id → Your API
```

## Simultaneous Multi-Provider Support

All four providers can be active simultaneously on the same API. The system automatically routes requests to the correct handler based on request characteristics.

### Example: Mixed Partner Ecosystem

```
Your API
├── Internal employees      → Entra ID (workforce tenant)
├── B2C customers          → Entra External ID (customer tenant)
├── Enterprise partner A   → External (BYOID) - uses Okta
├── Enterprise partner B   → External (BYOID) - uses Auth0
├── Legacy integration     → API Key
└── Financial partner      → Signed Request
```

All these authentication methods work on the same endpoints, with authorization determined by roles rather than authentication method.

## Security Design Principles

### 1. Fail-Closed Architecture

The system never silently falls back to an unrelated authentication scheme:

| Scenario | Behavior |
|----------|----------|
| Unrecognized JWT audience | **Rejected** (not sent to random Entra instance) |
| No matching credentials | **Rejected** (not sent to "default" scheme) |
| Conflicting indicators | **Rejected** (not guessed) |

### 2. Conflict Detection

When a request contains conflicting authentication indicators, it's rejected rather than guessing:

```
X-Api-Key + X-Tenant-Slug → Rejected (ambiguous)
X-Api-Key only           → API Key handler
X-Tenant-Slug + Bearer   → External (BYOID) handler
```

This prevents "scheme shopping" attacks where an attacker sends multiple credentials hoping one works.

### 3. Scheme Selection Priority

The selection order is designed for security:

1. **Conflict detection first** - Prevents ambiguous requests from authenticating
2. **Most specific matches** - API key headers checked before generic Bearer tokens
3. **Audience matching** - JWT tokens routed by audience claim
4. **Rejection last** - No match means rejection, not fallback

### 4. Cross-Scheme Authorization

Authorization policies can work across all authentication methods using role-based access control:

```csharp
// This policy accepts authentication from ANY provider
// Authorization is determined by the "partner" role, not the auth method
builder.AddAuthorization()
    .AddPolicy("PartnerAccess", policy => {
        policy
            .AddAuthenticationSchemes(AuthorizationSchemes.Dynamic)
            .RequireAuthenticatedUser()
            .RequireRole("partner");
    });
```

The `auth_scheme` claim identifies which handler authenticated the request, enabling scheme-specific logic when needed.

## Dynamic Scheme Selection Flow

```
Request arrives
    │
    ▼
Endpoint requires authorization?
    │
    ├── NO  → Request proceeds (no authentication)
    │
    └── YES → Dynamic selector evaluates request
                 │
                 ▼
              1. Conflicting indicators? → Reject (401)
                 │
              2. API Key header? → API Key handler
                 │
              3. Signed Request headers? → Signed Request handler
                 │
              4. Tenant identifier + Bearer? → External (BYOID) handler
                 │
              5. Bearer with recognized audience? → Entra handler
                 │
              6. No match → Reject (401)
```

## Token Validation

### Entra ID Tokens
- Validated against Microsoft's OIDC metadata
- Audience must match configured app registration
- Standard JWT validation (signature, expiry, issuer)

### External (BYOID) Tokens
- Tenant configuration retrieved from database
- OIDC discovery document fetched from partner's IdP
- Standard JWT validation against partner's signing keys
- Supports any OIDC-compliant identity provider

### API Keys
- Validated against configured or database-backed key store
- Supports key rotation and revocation
- Optional caching for performance

### Signed Requests
- HMAC-SHA256 signature validation
- Timestamp validation prevents replay attacks
- Client ID maps to shared secret

## API Usage

### Basic Setup

```csharp
// Just Entra and static API keys from appsettings.json
builder.AddAuthorization();
```

### With Dynamic Providers

Dynamic providers (database-backed resolvers) are configured via the `CirreumAuthorizationBuilder`:

```csharp
builder.AddAuthorization(auth => auth
    // External (BYOID) for customer IdPs
    .AddExternal<DatabaseTenantResolver>()
    // Dynamic API keys for database-backed keys
    .AddDynamicApiKeys<DatabaseApiKeyResolver>(["X-Api-Key"])
    // Signed requests for external partners
    .AddSignedRequest<DatabaseSignedRequestResolver>()
)
// Standard ASP.NET Core policy configuration
.AddPolicy("TenantAccess", policy => {
    policy
        .AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("tenant:user");
});
```

The builder pattern:
- Groups Cirreum-specific authentication configuration
- Returns `AuthorizationBuilder` for standard policy configuration
- Ensures providers are registered after the core authorization setup

## Configuration Example

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
              "Audience": "api://internal-app",
              "TenantId": "your-workforce-tenant-id"
            },
            "ExternalCustomers": {
              "Enabled": true,
              "Audience": "api://customer-app",
              "TenantId": "your-external-tenant-id"
            }
          }
        },
        "External": {
          "Instances": {
            "default": {
              "Enabled": true,
              "TenantIdentifierSource": "Header",
              "TenantHeaderName": "X-Tenant-Slug"
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
        }
      }
    }
  }
}
```

## Predefined Authorization Policies

| Policy | Description | Allowed Roles |
|--------|-------------|---------------|
| `System` | Primary Entra only, system processes | `App.System` |
| `StandardAdmin` | Any auth method, admin access | `App.System`, `App.Admin` |
| `StandardManager` | Any auth method, management access | + `App.Manager` |
| `StandardAgent` | Any auth method, service access | + `App.Agent` |
| `StandardInternal` | Any auth method, internal access | + `App.Internal` |
| `Standard` | Any auth method, all users | + `App.User` |

**Note:** The `System` policy is restricted to the primary Entra instance only, ensuring system-level operations cannot be performed via API keys or other mechanisms.

## Audit and Compliance

Each authenticated request includes:

- `auth_scheme` claim identifying the authentication method used
- Standard claims from the identity provider
- Normalized role claims for consistent authorization

This enables:
- Audit trails showing which authentication method was used
- Compliance reporting by authentication type
- Fine-grained access analysis

## Security Considerations for Partners

### OAuth/OIDC vs Signed Request: Different Security Models

A common misconception is that OAuth/OIDC is inherently "more secure" than Signed Request authentication. In reality, they solve different security problems and have different threat models.

#### What OAuth/OIDC (External/BYOID) Provides

| Strength | Description |
|----------|-------------|
| Delegated authorization | User grants limited access without sharing credentials |
| Identity federation | Leverage existing enterprise identity infrastructure |
| Token scoping | Tokens can be scoped to specific permissions |
| Standards-based | Well-audited, widely implemented specification |
| Short-lived tokens | Tokens expire, limiting exposure window |

#### What Signed Request Provides

| Strength | Description |
|----------|-------------|
| No bearer tokens | Nothing to intercept - signature proves possession of secret |
| Request integrity | Entire request body can be signed, detecting tampering |
| Replay protection | Timestamp validation prevents request replay |
| No network dependencies | No IdP availability required at request time |
| Simpler key management | Shared secrets vs. certificate/key infrastructure |

### Potential Partner Concerns with External (BYOID)

Security-conscious partners may raise these concerns about BYOID authentication:

#### 1. Token Exposure
**Concern:** Partner JWT tokens are transmitted to your API.

**Reality:** Bearer tokens can be intercepted if TLS is compromised. Some partners prefer approaches where credentials never leave their network.

**Mitigation:** HTTPS is required (`RequireHttpsMetadata: true`). For higher security, partners can use Signed Request instead.

#### 2. OIDC Metadata Dependency
**Concern:** Your system fetches their `/.well-known/openid-configuration` at runtime.

**Reality:** If their IdP has strict firewall rules, doesn't expose public OIDC endpoints, or experiences downtime, authentication fails.

**Mitigation:** OIDC metadata is cached. Partners with strict network policies should consider Signed Request.

#### 3. Token Revocation Lag
**Concern:** If a partner revokes a token, your system won't know until the token expires.

**Reality:** Standard JWT validation doesn't include real-time revocation checks. A compromised token remains valid until expiry.

**Mitigation:** Partners should use short-lived tokens (5-15 minutes). Token introspection could be added for real-time revocation (not currently implemented).

#### 4. Claim Trust
**Concern:** Your system trusts whatever claims come in their token.

**Reality:** If their IdP is compromised, attackers could mint valid tokens with elevated claims.

**Mitigation:** This is inherent to federation. Role mapping and claim validation provide defense in depth. Critical operations should require additional verification.

#### 5. No Proof-of-Possession
**Concern:** Standard bearer tokens can be replayed if intercepted.

**Reality:** Unlike Signed Request (which proves the caller has the secret), bearer tokens only prove the caller *has* the token.

**Mitigation:** Short token lifetimes reduce exposure. DPoP (Demonstrating Proof-of-Possession) could be added for stronger guarantees (not currently implemented).

#### 6. No mTLS Option
**Concern:** Some regulated industries require mutual TLS at the transport layer.

**Reality:** The current implementation relies on standard TLS, not client certificates.

**Mitigation:** mTLS can be implemented at the infrastructure layer (API gateway, load balancer) independently of application authentication.

### When to Recommend Each Method

| Partner Profile | Recommended Method | Rationale |
|-----------------|-------------------|-----------|
| Enterprise with existing IdP | External (BYOID) | Leverages their identity investment |
| Startup/small partner | API Key | Simplest integration path |
| Financial services | Signed Request | Request integrity, no bearer tokens |
| Healthcare/regulated | Signed Request + mTLS | Compliance requirements |
| Consumer-facing app | Entra External ID | You control the identity lifecycle |
| Internal microservices | API Key or Entra | Depends on security posture |

### Security Comparison Matrix

| Security Property | External (BYOID) | Signed Request | API Key |
|-------------------|------------------|----------------|---------|
| Token interception risk | Medium | None | High |
| Request tampering detection | No | Yes | No |
| Replay attack prevention | Token expiry only | Timestamp validation | None |
| IdP dependency at runtime | Yes | No | No |
| Real-time revocation | No (requires introspection) | Yes (remove secret) | Yes (remove key) |
| User identity support | Yes | No (M2M only) | No (M2M only) |
| Credential exposure | Token visible in headers | Only signature visible | Key visible in headers |
| Key/secret rotation | IdP handles | Manual coordination | Manual coordination |

### Mitigations Already In Place

The External (BYOID) implementation includes these security measures:

- **HTTPS required** - `RequireHttpsMetadata: true` by default
- **Standard JWT validation** - Signature, expiry, issuer, audience all verified per RFC 9068
- **`alg: "none"` rejection** - Unsigned tokens are always rejected
- **Tenant isolation** - Each tenant's tokens validated against their specific IdP
- **Fail-closed design** - Unrecognized tokens rejected, not passed to wrong handler
- **Conflict detection** - Ambiguous requests rejected
- **Metadata caching** - Reduces IdP dependency and improves resilience
- **Token type validation** - ID tokens (`typ: id_token`) are always rejected; optional strict mode requires `typ: at+jwt`
- **Client ID (azp) validation** - Optional per-tenant restriction of allowed client applications
- **RFC 6750 error responses** - 401 responses include `WWW-Authenticate: Bearer ... error="invalid_token"`

### Token Type Validation

The handler prevents ID tokens from being used as access tokens:

| `typ` value | `RequireAccessTokenType = false` (default) | `RequireAccessTokenType = true` |
|-------------|-------------------------------------------|--------------------------------|
| `null`/missing | **Rejected** | **Rejected** |
| `id_token` | **Rejected** | **Rejected** |
| `JWT` | Accepted | Rejected |
| `at+jwt` | Accepted | Accepted |

ID tokens (`typ: "id_token"`) are **always rejected** regardless of configuration - they should never be used as Bearer tokens.

For strict RFC 9068 compliance, enable `RequireAccessTokenType` per tenant to require `at+jwt` tokens. Only enable this if the tenant's IdP supports RFC 9068.

### Client ID (azp) Validation

Prevents tokens issued to one client application from being used by another:

```
Partner has two apps:
├── partner-web-app (trusted, full access)
└── partner-mobile-app (limited access)

With AllowedClientIds: ["partner-web-app"]
├── Token from partner-web-app → Accepted
└── Token from partner-mobile-app → Rejected (401)
```

This prevents lateral movement if a lower-trust client is compromised.

### Future Security Enhancements (Roadmap)

Potential additions based on partner feedback:

1. **Token Introspection** - Real-time revocation checking via RFC 7662
2. **DPoP Support** - Proof-of-possession for bearer tokens via RFC 9449
3. **Certificate-Bound Tokens** - mTLS-bound access tokens via RFC 8705

## Summary

This architecture provides:

1. **Flexibility** - Support multiple partner authentication models simultaneously
2. **Security** - Fail-closed design prevents authentication confusion attacks
3. **Simplicity** - Single API surface with automatic scheme routing
4. **Extensibility** - Add new partners/IdPs without code changes
5. **Compliance** - Full audit trail of authentication methods used
6. **Choice** - Partners select the authentication method matching their security requirements

Partners can be onboarded using whichever authentication method best fits their capabilities and security requirements, all while accessing the same API endpoints with role-based authorization.

The key insight is that **OAuth/OIDC and Signed Request are complementary, not competing**. OAuth excels at user identity and delegated authorization; Signed Request excels at M2M integrity and non-repudiation. Offering both lets partners choose based on their specific threat model.
