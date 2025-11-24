# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Build
```bash
dotnet build Cirreum.Runtime.Authorization.slnx
```

### Build Release
```bash
dotnet build Cirreum.Runtime.Authorization.slnx --configuration Release
```

### Restore Dependencies
```bash
dotnet restore Cirreum.Runtime.Authorization.slnx
```

### Create NuGet Package
```bash
dotnet pack Cirreum.Runtime.Authorization.slnx --configuration Release
```

### Run Tests
No test projects found in the current structure. Tests may be in a separate repository or added later.

## Architecture Overview

This is a .NET 10.0 library that provides runtime authorization configuration for the Cirreum Framework. The project follows a layered architecture pattern with:

**Core Components:**
- `HostingExtensions.cs` - Extension methods for configuring authentication and authorization in ASP.NET Core applications
- Dynamic authentication scheme selector that routes to appropriate providers based on JWT audience
- Support for multiple authorization providers (currently Entra/Azure AD)
- Predefined authorization policies with hierarchical role-based access control

**Key Dependencies:**
- `Cirreum.Core` - Core framework functionality
- `Cirreum.Authorization.Entra` - Azure AD/Entra ID authorization provider
- `Cirreum.Runtime.AuthorizationProvider` - Base authorization provider abstractions

**Authorization Policies:**
The framework defines standard policies with cascading role permissions:
- `System` - Restricted to primary scheme, requires AppSystemRole
- `Standard` - All roles (System, Admin, Manager, Agent, Internal, User)
- `StandardInternal` - Internal roles and above
- `StandardAgent` - Agent roles and above  
- `StandardManager` - Manager roles and above
- `StandardAdmin` - Admin and System only

**Runtime Types:**
The authorization system only supports WebApi and WebApp runtime types. It uses a dynamic authentication scheme selector that inspects JWT tokens to route to the appropriate authentication provider based on the audience claim.