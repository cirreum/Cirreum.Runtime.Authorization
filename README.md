# Cirreum.Runtime.Authorization

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Runtime.Authorization.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authorization/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Runtime.Authorization.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Runtime.Authorization/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Runtime.Authorization?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Runtime.Authorization/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Runtime.Authorization?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Runtime.Authorization/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Streamlined authentication and authorization configuration for ASP.NET Core applications**

## Overview

**Cirreum.Runtime.Authorization** provides a unified approach to configuring authentication and authorization in ASP.NET Core applications. It supports multiple authorization providers, dynamic scheme selection based on JWT audiences, and predefined role-based authorization policies.

## Features

- **Dynamic Authentication** - Automatically routes authentication to the appropriate provider based on JWT audience claims
- **Multi-Provider Support** - Extensible architecture supporting multiple authorization providers (currently includes Entra/Azure AD)
- **Predefined Policies** - Hierarchical role-based authorization policies for common scenarios
- **WebApi & WebApp Support** - Designed specifically for web-based runtime environments
- **Seamless Integration** - Simple extension methods for ASP.NET Core host configuration

## Installation

```bash
dotnet add package Cirreum.Runtime.Authorization
```

## Usage

```csharp
var builder = WebApplication.CreateBuilder(args);

// Add authorization with default configuration
builder.AddAuthorization();

// Or with custom authentication options
builder.AddAuthorization(auth => {
    auth.DefaultScheme = "MyScheme";
    auth.DefaultChallengeScheme = "MyScheme";
});

var app = builder.Build();
```

## Configuration

Configure the default authorization scheme in your `appsettings.json`:

```json
{
  "Cirreum": {
    "Authorization": {
      "Default": "YourDefaultScheme"
    }
  }
}
```

## Authorization Policies

The library includes predefined authorization policies with hierarchical role access:

- **System** - Highest privilege, restricted to primary scheme only
- **StandardAdmin** - Administrative access (System + Admin roles)
- **StandardManager** - Management access (System + Admin + Manager roles)
- **StandardAgent** - Agent access (System + Admin + Manager + Agent roles)
- **StandardInternal** - Internal access (System + Admin + Manager + Internal roles)
- **Standard** - All authenticated users (all roles including User)

## Contribution Guidelines

1. **Be conservative with new abstractions**  
   The API surface must remain stable and meaningful.

2. **Limit dependency expansion**  
   Only add foundational, version-stable dependencies.

3. **Favor additive, non-breaking changes**  
   Breaking changes ripple through the entire ecosystem.

4. **Include thorough unit tests**  
   All primitives and patterns should be independently testable.

5. **Document architectural decisions**  
   Context and reasoning should be clear for future maintainers.

6. **Follow .NET conventions**  
   Use established patterns from Microsoft.Extensions.* libraries.

## Versioning

Cirreum.Runtime.Authorization follows [Semantic Versioning](https://semver.org/):

- **Major** - Breaking API changes
- **Minor** - New features, backward compatible
- **Patch** - Bug fixes, backward compatible

Given its foundational role, major version bumps are rare and carefully considered.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**  
*Layered simplicity for modern .NET*