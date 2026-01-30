namespace Microsoft.AspNetCore.Hosting;

using Cirreum;
using Cirreum.Authorization;
using Cirreum.Authorization.ApiKey;
using Cirreum.Authorization.ApiKey.Configuration;
using Cirreum.Authorization.Configuration;
using Cirreum.Authorization.External;
using Cirreum.AuthorizationProvider;
using Cirreum.AuthorizationProvider.ApiKey;
using Cirreum.AuthorizationProvider.SignedRequest;
using Cirreum.Providers;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IO;
using Microsoft.Net.Http.Headers;

public static class HostingExtensions {

	private class ConfigureAuthorizationMarker { }

	/// <summary>
	/// Registers all configured authentication providers and authorization policies.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This method configures the unified authorization system with support for:
	/// </para>
	/// <list type="bullet">
	///   <item><b>Entra ID</b> - Azure AD/Entra JWT tokens (configured in appsettings)</item>
	///   <item><b>API Key</b> - Static keys from config, dynamic keys via resolver</item>
	///   <item><b>Signed Request</b> - HMAC-signed requests (requires resolver)</item>
	///   <item><b>External (BYOID)</b> - Multi-tenant customer IdP tokens (requires resolver)</item>
	/// </list>
	/// <para>
	/// Entra and static API keys are configured via <c>Cirreum:Authorization:Providers</c>
	/// in appsettings.json. Dynamic providers require additional registration via the
	/// <see cref="CirreumAuthorizationBuilder"/>:
	/// </para>
	/// <list type="bullet">
	///   <item><see cref="CirreumAuthorizationBuilder.AddDynamicApiKeys{TResolver}"/> for database-backed API keys</item>
	///   <item><see cref="CirreumAuthorizationBuilder.AddSignedRequest{TResolver}"/> for signed requests</item>
	///   <item><see cref="CirreumAuthorizationBuilder.AddExternal{TResolver}"/> for BYOID</item>
	/// </list>
	/// <para>
	/// See <see cref="AuthorizationPolicies"/> for predefined role-based policies.
	/// </para>
	/// </remarks>
	/// <param name="builder">The host application builder.</param>
	/// <param name="authentication">Optional authentication options configuration.</param>
	/// <returns>The <see cref="AuthorizationBuilder"/> for chaining additional configuration.</returns>
	/// <example>
	/// <code>
	/// // Basic setup - Entra and static API keys from config
	/// builder.AddAuthorization();
	///
	/// // With External (BYOID) for customer IdPs
	/// builder.AddAuthorization(auth => auth
	///     .AddExternal&lt;DatabaseTenantResolver&gt;()
	/// );
	///
	/// // Full setup with all providers
	/// builder.AddAuthorization(auth => auth
	///     .AddExternal&lt;DatabaseTenantResolver&gt;()
	///     .AddDynamicApiKeys&lt;DatabaseApiKeyResolver&gt;(["X-Api-Key"])
	///     .AddSignedRequest&lt;DatabaseSignedRequestResolver&gt;()
	/// );
	/// </code>
	/// </example>
	public static AuthorizationBuilder AddAuthorization(
		this IHostApplicationBuilder builder,
		Action<AuthenticationOptions>? authentication = null) {

		// Check if already registered using a marker service
		if (builder.Services.IsMarkerTypeRegistered<ConfigureAuthorizationMarker>()) {
			return builder.Services.AddAuthorizationBuilder();
		}

		// Mark as registered
		builder.Services.MarkTypeAsRegistered<ConfigureAuthorizationMarker>();

		// Ensure we have a recyclable memory stream manager for efficient stream handling
		builder.Services.TryAddSingleton<RecyclableMemoryStreamManager>();

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

		// Resolve primary scheme - used exclusively for the System policy
		var primaryScheme = builder.Configuration.GetValue<string>("Cirreum:Authorization:PrimaryScheme");
		if (string.IsNullOrWhiteSpace(primaryScheme)) {
			throw new InvalidOperationException(
				"Missing required 'Cirreum:Authorization:PrimaryScheme' configuration. " +
				"This must be set to one of your configured authentication scheme names.");
		}

		// Get the registry using the helper method
		var registeredSchemes = builder.Services.GetAuthorizationSchemeRegistry();

		//
		// Add Authentication
		//
		var authenticationBuilder = builder.Services
			.AddAuthentication(o => {
				o.DefaultScheme = AuthorizationSchemes.Dynamic;
				o.DefaultChallengeScheme = AuthorizationSchemes.Dynamic;
				authentication?.Invoke(o);
			});

		// Store the authentication builder for extension methods to use
		builder.Services.AddSingleton(authenticationBuilder);


		//
		// Register Authorization Providers...
		//

		// Register Entra (JWT) provider
		builder.RegisterAuthorizationProvider<
			EntraAuthorizationRegistrar,
			EntraAuthorizationSettings,
			EntraAuthorizationInstanceSettings>(authenticationBuilder);

		// Register API Key provider from configuration (static api keys)
		// This populates the ApiKeyClientRegistry with configured keys
		builder.RegisterAuthorizationProvider<
			ApiKeyAuthorizationRegistrar,
			ApiKeyAuthorizationSettings,
			ApiKeyAuthorizationInstanceSettings>(authenticationBuilder);

		// Register External (BYOID) provider from configuration
		// This registers the handler and core services; resolver is added via AddExternalAuth<T>()
		builder.RegisterAuthorizationProvider<
			ExternalAuthorizationRegistrar,
			ExternalAuthorizationSettings,
			ExternalAuthorizationInstanceSettings>(authenticationBuilder);

		// Register core API key services for the Dynamic ApiKey resolver
		RegisterCoreApiKeyServices(builder.Services);

		// Register the default configuration-based resolver if not already registered
		// This is so we can support both static (config) and dynamic (db) API keys
		builder.Services.TryAddSingleton<IApiKeyClientResolver>(sp => {
			var registry = sp.GetRequiredService<ApiKeyClientRegistry>();
			var validator = sp.GetRequiredService<IApiKeyValidator>();
			var logger = sp.GetRequiredService<ILogger<ConfigurationApiKeyClientResolver>>();
			return new ConfigurationApiKeyClientResolver(registry, validator, logger);
		});

		// Register the ambiguous request rejection scheme
		authenticationBuilder.AddScheme<AmbiguousRequestAuthenticationOptions, AmbiguousRequestAuthenticationHandler>(
			AuthorizationSchemes.Ambiguous, null);

		// Ensure primary scheme is registered
		if (!registeredSchemes.Schemes.Contains(primaryScheme, StringComparer.OrdinalIgnoreCase)) {
			throw new InvalidOperationException(
				$"PrimaryScheme '{primaryScheme}' is not a registered authentication scheme. " +
				$"Available schemes: {string.Join(", ", registeredSchemes.Schemes)}");
		}

		//
		// Register Scheme Policy
		//
		authenticationBuilder.AddPolicyScheme(AuthorizationSchemes.Dynamic, "Dynamic Authentication Selector", options => {
			options.ForwardDefaultSelector = context => {

				// Get External (BYOID) options for conflict detection and scheme selection
				var externalOptions = context.RequestServices.GetService<ExternalAuthenticationOptions>();

				// Collect API key header names for conflict detection
				var apiKeyHeaders = new List<string>();
				foreach (var (headerName, _) in registeredSchemes.HeaderSchemes) {
					apiKeyHeaders.Add(headerName);
				}
				var apiKeyResolver = context.RequestServices.GetService<IApiKeyClientResolver>();
				if (apiKeyResolver is not null) {
					apiKeyHeaders.AddRange(apiKeyResolver.SupportedHeaders);
				}

				// 1. Check for conflicting auth indicators (API key header + tenant slug header)
				// This prevents "scheme shopping" attacks where an attacker sends both
				if (externalOptions is not null &&
					ExternalSchemeSelector.HasConflictingIndicators(context, externalOptions, apiKeyHeaders)) {
					// Route to dedicated rejection scheme - always fails with clear error
					return AuthorizationSchemes.Ambiguous;
				}

				// 2. Check statically registered header-based schemes (API keys from configuration)
				foreach (var (headerName, scheme) in registeredSchemes.HeaderSchemes) {
					if (context.Request.Headers.ContainsKey(headerName)) {
						return scheme;
					}
				}

				// 3. Check headers from dynamic resolver (database-backed API keys)
				if (apiKeyResolver is not null) {
					foreach (var headerName in apiKeyResolver.SupportedHeaders) {
						if (context.Request.Headers.ContainsKey(headerName)) {
							// Ensure the scheme is registered
							var scheme = $"Header:{headerName}";
							if (!registeredSchemes.HeaderSchemes.ContainsKey(headerName)) {
								// Dynamically register this header scheme
								registeredSchemes.RegisterHeaderScheme(headerName, scheme);
							}
							return scheme;
						}
					}
				}

				// 4. Check for signed request authentication
				// Requires all three headers: X-Client-Id, X-Timestamp, and X-Signature
				var signedRequestResolver = context.RequestServices.GetService<ISignedRequestClientResolver>();
				if (signedRequestResolver is not null) {
					var signatureOptions =
						context.RequestServices.GetService<IOptions<SignatureValidationOptions>>()?.Value
						?? new SignatureValidationOptions();

					if (context.Request.Headers.ContainsKey(signatureOptions.ClientIdHeaderName) &&
						context.Request.Headers.ContainsKey(signatureOptions.TimestampHeaderName) &&
						context.Request.Headers.ContainsKey(signatureOptions.SignatureHeaderName)) {
						return SignedRequestDefaults.AuthenticationScheme;
					}
				}

				// 5. Check for External (BYOID) authentication
				// Requires tenant identifier (header, path, or subdomain) + bearer token
				if (externalOptions is not null &&
					ExternalSchemeSelector.ShouldHandleRequest(context, externalOptions)) {
					return ExternalDefaults.AuthenticationScheme;
				}

				// 6. JWT Bearer token routing by audience (Entra and other static IdPs)
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

				// 7. No matching scheme - reject the request
				// This prevents silent fallback to an unrelated scheme
				return AuthorizationSchemes.Ambiguous;
			};
		});

		//
		// Register Authorization Policies
		//

		// System only access - Always restricted to primary scheme only
		// This ensures system-level access requires authentication via the designated
		// primary Entra instance, not through API keys or other mechanisms
		authorizationBuilder.AddPolicy(AuthorizationPolicies.System, policy => {
			policy
				.AddAuthenticationSchemes(primaryScheme)
				.RequireAuthenticatedUser()
				.RequireRole(ApplicationRoles.AppSystemRole);
		});

		//
		// The remaining core polices which support multi-scheme
		//
		authorizationBuilder.AddCorePolicies(AuthorizationSchemes.Dynamic);

		return authorizationBuilder;
	}

	/// <summary>
	/// Registers all configured authentication providers and authorization policies,
	/// with additional configuration for dynamic authentication schemes.
	/// </summary>
	/// <param name="builder">The host application builder.</param>
	/// <param name="configure">Configuration action for additional authentication schemes.</param>
	/// <param name="authentication">Optional authentication options configuration.</param>
	/// <returns>The <see cref="AuthorizationBuilder"/> for chaining additional configuration.</returns>
	/// <example>
	/// <code>
	/// builder.AddAuthorization(auth => auth
	///     .AddSignedRequest&lt;DatabaseSignedRequestResolver&gt;()
	///     .AddDynamicApiKeys&lt;DatabaseApiKeyResolver&gt;(["X-Api-Key"])
	///     .AddExternal&lt;DatabaseTenantResolver&gt;()
	/// )
	/// .AddPolicy("CustomPolicy", policy => ...);
	/// </code>
	/// </example>
	public static AuthorizationBuilder AddAuthorization(
		this IHostApplicationBuilder builder,
		Action<CirreumAuthorizationBuilder> configure,
		Action<AuthenticationOptions>? authentication = null) {

		var authorizationBuilder = builder.AddAuthorization(authentication);

		var cirreumBuilder = new CirreumAuthorizationBuilder(
			builder.Services,
			authorizationBuilder);

		configure(cirreumBuilder);

		return authorizationBuilder;
	}

	private static void RegisterCoreApiKeyServices(IServiceCollection services) {

		// Ensure ApiKeyClientRegistry is registered even if no ApiKeys are configured.
		// This is needed because IApiKeyClientResolver depends on it, and the registry
		// may not be created if RegisterAuthorizationProvider returns early due to
		// no static ApiKey instances included in appsettings.
		_ = services.GetApiKeyClientRegistry();

		// Register validation options with defaults
		services.TryAddSingleton(Options.Create(new ApiKeyValidationOptions()));
		services.TryAddSingleton(Options.Create(new ApiKeyCachingOptions()));

		// Register validator
		services.TryAddSingleton<IApiKeyValidator, DefaultApiKeyValidator>();

		// Ensure memory cache is available for caching scenarios
		services.AddMemoryCache();

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