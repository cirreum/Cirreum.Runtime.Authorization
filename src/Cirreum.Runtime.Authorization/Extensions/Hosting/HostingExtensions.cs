namespace Microsoft.AspNetCore.Hosting;

using Cirreum;
using Cirreum.Authorization;
using Cirreum.Authorization.Configuration;
using Cirreum.AuthorizationProvider;
using Cirreum.AuthorizationProvider.ApiKey;
using Cirreum.AuthorizationProvider.ApiKey.Configuration;
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
	/// Add support for Authentication/Authorization by registering any configured providers
	/// and associated instances including the core application authorization policies.
	/// </summary>
	/// <remarks>
	/// <para>
	/// API key and Entra (JWT) authentication are configured via appsettings.json under
	/// <c>Cirreum:Authorization:Providers</c>. Static API keys work automatically.
	/// </para>
	/// <para>
	/// For dynamic API key resolution (e.g., database-backed), use
	/// <see cref="ApiKeyAuthorizationBuilderExtensions.AddDynamicApiKeys{TResolver}"/>.
	/// Dynamic resolution is added on top of static configuration - both work together.
	/// </para>
	/// <para>
	/// See <see cref="AuthorizationPolicies"/> for available authorization policies.
	/// </para>
	/// </remarks>
	/// <returns>The <see cref="AuthorizationBuilder"/> for chaining.</returns>
	/// <example>
	/// <code>
	/// // Static keys only (from appsettings/KeyVault)
	/// builder
	///     .AddAuthorization()
	///     .AddPolicy("Broker", policy => {
	///         policy
	///             .AddAuthenticationSchemes("Header:X-Api-Key")
	///             .RequireAuthenticatedUser()
	///             .RequireRole("broker");
	///     });
	///
	/// // Add dynamic keys (database-backed) - static keys still work
	/// builder
	///     .AddAuthorization()
	///     .AddDynamicApiKeys&lt;DatabaseApiKeyResolver&gt;(o => o.WithCaching())
	///     .AddPolicy("Partner", policy => {
	///         policy
	///             .AddAuthenticationSchemes("Header:X-Api-Key")
	///             .RequireAuthenticatedUser()
	///             .RequireRole("partner");
	///     });
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

		// Register API Key provider from configuration (backward compatible)
		// This populates the ApiKeyClientRegistry with configured keys
		builder.RegisterAuthorizationProvider<
			ApiKeyAuthorizationRegistrar,
			ApiKeyAuthorizationSettings,
			ApiKeyAuthorizationInstanceSettings>(authenticationBuilder);

		// Register core API key services for the new resolver pattern
		RegisterCoreApiKeyServices(builder.Services);

		// Register the default configuration-based resolver if not already registered
		// This enables backward compatibility will still work with configured keys
		builder.Services.TryAddSingleton<IApiKeyClientResolver>(sp => {
			var registry = sp.GetRequiredService<ApiKeyClientRegistry>();
			var validator = sp.GetRequiredService<IApiKeyValidator>();
			var logger = sp.GetRequiredService<ILogger<ConfigurationApiKeyClientResolver>>();
			return new ConfigurationApiKeyClientResolver(registry, validator, logger);
		});

		//
		// Register Scheme Policy
		//
		authenticationBuilder.AddPolicyScheme(dynamicScheme, "Dynamic Authentication Selector", options => {
			options.ForwardDefaultSelector = context => {

				// Check statically registered header-based schemes (API keys from configuration)
				foreach (var (headerName, scheme) in registeredSchemes.HeaderSchemes) {
					if (context.Request.Headers.ContainsKey(headerName)) {
						return scheme;
					}
				}

				// Check headers from dynamic resolver (database-backed API keys)
				var resolver = context.RequestServices.GetService<IApiKeyClientResolver>();
				if (resolver is not null) {
					foreach (var headerName in resolver.SupportedHeaders) {
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

				// Check for signed request authentication
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