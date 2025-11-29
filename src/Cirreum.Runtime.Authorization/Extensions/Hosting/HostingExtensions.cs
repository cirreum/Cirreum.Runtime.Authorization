namespace Microsoft.AspNetCore.Hosting;

using Cirreum;
using Cirreum.Authorization;
using Cirreum.Authorization.Configuration;
using Cirreum.AuthorizationProvider;
using Cirreum.AuthorizationProvider.ApiKey;
using Cirreum.AuthorizationProvider.ApiKey.Configuration;
using Cirreum.Providers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Net.Http.Headers;

public static class HostingExtensions {
	private class ConfigureAuthorizationMarker { }

	/// <summary>
	/// Add support for Authentication/Authorization by registering any configured providers
	/// and associated instances including the core application authorization policies.
	/// </summary>
	/// <remarks>
	/// <para>
	/// See <see cref="AuthorizationPolicies"/>
	/// </para>
	/// </remarks>
	/// <returns>The <see cref="AuthorizationBuilder"/> for chaining.</returns>
	public static AuthorizationBuilder AddAuthorization(
		this IHostApplicationBuilder builder,
		Action<AuthenticationOptions>? authentication = null) {
		// Check if already registered using a marker service		
		if (builder.Services.IsMarkerTypeRegistered<ConfigureAuthorizationMarker>()) {
			return builder.Services.AddAuthorizationBuilder();
		}

		// Mark as registered
		builder.Services.MarkTypeAsRegistered<ConfigureAuthorizationMarker>();

		// Create a new authorization builder
		var authorizationBuilder = builder.Services.AddAuthorizationBuilder();

		// WebApi or WebApp
		if (builder.Properties.TryGetValue(DomainContext.RuntimeTypeKey, out var runtimeType) is false) {
			throw new InvalidOperationException("Missing required domain runtime type.");
		}
		var providerType = runtimeType switch {
			DomainRuntimeType.WebApi => ProviderRuntimeType.WebApi,
			DomainRuntimeType.WebApp => ProviderRuntimeType.WebApp,
			_ => throw new InvalidOperationException(
				$"Authorization Providers are only supported in WebApi or WebApp runtimes. Current runtime: {runtimeType}")
		};
		ProviderContext.SetRuntimeType(providerType);

		// Resolve default/primary scheme
		var defaultScheme = builder.Configuration.GetValue<string>("Cirreum:Authorization:Default");
		if (string.IsNullOrWhiteSpace(defaultScheme)) {
			throw new InvalidOperationException("Missing required default scheme for authorization.");
		}

		// Get the registry using the helper method
		var registeredSchemes = builder.Services.GetAuthorizationSchemeRegistry();

		//
		// Add Authentication
		//
		var dynamicScheme = "DynamicScheme";
		var authenticationBuilder = builder.Services
			.AddAuthentication(o => {
				o.DefaultScheme = dynamicScheme;
				o.DefaultChallengeScheme = dynamicScheme;
				authentication?.Invoke(o);
			});

		//
		// Register Authorization Providers...
		//

		builder
			.RegisterAuthorizationProvider<
				EntraAuthorizationRegistrar,
				EntraAuthorizationSettings,
				EntraAuthorizationInstanceSettings>(authenticationBuilder)
			.RegisterAuthorizationProvider<
				ApiKeyAuthorizationRegistrar,
				ApiKeyAuthorizationSettings,
				ApiKeyAuthorizationInstanceSettings>(authenticationBuilder);

		//
		// Register Scheme Policy
		//

		authenticationBuilder.AddPolicyScheme(dynamicScheme, "Dynamic Authentication Selector", options => {
			options.ForwardDefaultSelector = context => {
				// Check header-based schemes first (API keys, etc.)
				foreach (var (headerName, scheme) in registeredSchemes.HeaderSchemes) {
					if (context.Request.Headers.ContainsKey(headerName)) {
						return scheme;
					}
				}

				// JWT Bearer token routing by audience
				string? authValue = context.Request.Headers[HeaderNames.Authorization];
				if (!string.IsNullOrEmpty(authValue) && authValue.StartsWith("Bearer ")) {
					var token = authValue["Bearer ".Length..].Trim();
					var jwtHandler = new JsonWebTokenHandler();

					if (jwtHandler.CanReadToken(token)) {
						var jwt = jwtHandler.ReadJsonWebToken(token);
						var audience = jwt.GetPayloadValue<string>("aud");

						if (!string.IsNullOrEmpty(audience)) {
							var scheme = registeredSchemes.GetSchemeForAudience(audience);
							if (!string.IsNullOrEmpty(scheme)) {
								return scheme;
							}
						}
					}
				}

				return defaultScheme;
			};
		});

		//
		// Register Authorization Policies
		//

		// System only access - Always restricted to primary scheme only
		authorizationBuilder.AddPolicy(AuthorizationPolicies.System, policy => {
			policy
				.AddAuthenticationSchemes(defaultScheme)
				.RequireAuthenticatedUser()
				.RequireRole(ApplicationRoles.AppSystemRole);
		});

		//
		// The remaining core polices which support multi-scheme
		//
		authorizationBuilder.AddCorePolicies(dynamicScheme);

		return authorizationBuilder;
	}

	private static void AddCorePolicies(
		this AuthorizationBuilder builder,
		string authorizationScheme) {
		// Helper to configure policies with a single scheme
		void ConfigurePolicy(string policyName, params string[] roles) {
			builder.AddPolicy(policyName, policy => {
				// Add the dynamic scheme
				policy.AddAuthenticationSchemes(authorizationScheme);

				policy
					.RequireAuthenticatedUser()
					.RequireRole(roles);
			});
		}

		// Standard policies with varying role requirements
		ConfigurePolicy(
			AuthorizationPolicies.Standard,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole,
			ApplicationRoles.AppAgentRole,
			ApplicationRoles.AppInternalRole,
			ApplicationRoles.AppUserRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardInternal,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole,
			ApplicationRoles.AppInternalRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardAgent,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole,
			ApplicationRoles.AppAgentRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardManager,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole,
			ApplicationRoles.AppManagerRole);

		ConfigurePolicy(
			AuthorizationPolicies.StandardAdmin,
			ApplicationRoles.AppSystemRole,
			ApplicationRoles.AppAdminRole);
	}
}
