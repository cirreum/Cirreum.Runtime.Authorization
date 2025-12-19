namespace Microsoft.AspNetCore.Authorization;

using Cirreum.Authorization;
using Cirreum.AuthorizationProvider;
using Cirreum.AuthorizationProvider.ApiKey;
using Cirreum.AuthorizationProvider.ApiKey.Configuration;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Extension methods for configuring dynamic API key authorization on <see cref="AuthorizationBuilder"/>.
/// </summary>
public static class ApiKeyAuthorizationBuilderExtensions {

	private class ApiKeyDynamicMarker { }

	/// <summary>
	/// Adds dynamic API key resolution using a custom resolver (e.g., database-backed).
	/// </summary>
	/// <typeparam name="TResolver">
	/// The resolver type that implements <see cref="IApiKeyClientResolver"/>.
	/// </typeparam>
	/// <param name="builder">The authorization builder.</param>
	/// <param name="headers">The HTTP header names that will contain API keys (e.g., "X-Api-Key").</param>
	/// <param name="configure">Optional configuration for caching and validation.</param>
	/// <returns>The authorization builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// This method adds dynamic key resolution on top of any statically configured keys.
	/// Static keys from appsettings/KeyVault are checked first, then the dynamic resolver.
	/// </para>
	/// <para>
	/// You must specify the header names that your resolver will handle. This registers
	/// the authentication handlers for those headers at startup.
	/// </para>
	/// <para>
	/// Use the scheme pattern <c>"Header:{HeaderName}"</c> in your policies:
	/// <c>.AddAuthenticationSchemes("Header:X-Api-Key")</c>
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// builder
	///     .AddAuthorization()
	///     .AddDynamicApiKeys&lt;DatabaseApiKeyClientResolver&gt;(
	///         headers: ["X-Api-Key"],
	///         configure: options => {
	///             options.WithCaching(cache => {
	///                 cache.SuccessCacheDuration = TimeSpan.FromMinutes(5);
	///             });
	///         })
	///     .AddPolicy("PartnerAccess", policy => {
	///         policy
	///             .AddAuthenticationSchemes("Header:X-Api-Key")
	///             .RequireAuthenticatedUser()
	///             .RequireRole("partner");
	///     });
	/// </code>
	/// </example>
	public static AuthorizationBuilder AddDynamicApiKeys<TResolver>(
		this AuthorizationBuilder builder,
		string[] headers,
		Action<DynamicApiKeyOptions>? configure = null)
		where TResolver : class, IApiKeyClientResolver {

		ArgumentNullException.ThrowIfNull(headers);
		if (headers.Length == 0) {
			throw new ArgumentException("At least one header must be specified", nameof(headers));
		}

		var services = builder.Services;

		// Check if already registered
		if (services.IsMarkerTypeRegistered<ApiKeyDynamicMarker>()) {
			return builder;
		}
		services.MarkTypeAsRegistered<ApiKeyDynamicMarker>();

		// Build options
		var options = new DynamicApiKeyOptions();
		configure?.Invoke(options);

		// Apply validation configuration if provided
		if (options.ValidationConfiguration is not null) {
			services.Configure(options.ValidationConfiguration);
		}

		// Apply caching configuration if provided
		if (options.CachingEnabled && options.CachingConfiguration is not null) {
			services.Configure(options.CachingConfiguration);
		}

		// Register the custom resolver type
		services.TryAddScoped<TResolver>();

		// Remove the default configuration-only resolver and replace with composite
		ReplaceResolverWithComposite<TResolver>(services, options);

		// Register authentication handlers for the specified headers
		RegisterDynamicHeaders(services, headers);

		return builder;
	}

	private static void RegisterDynamicHeaders(IServiceCollection services, string[] headers) {
		// Get the authentication builder that was stored during AddAuthorization
		var authBuilderDescriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(AuthenticationBuilder) &&
			d.ImplementationInstance is not null);

		if (authBuilderDescriptor?.ImplementationInstance is not AuthenticationBuilder authBuilder) {
			throw new InvalidOperationException(
				"AddDynamicApiKeys must be called after AddAuthorization. " +
				"Ensure you call builder.AddAuthorization() first.");
		}

		// Get the scheme registry
		var schemeRegistry = services.GetAuthorizationSchemeRegistry();

		// Register each header
		foreach (var headerName in headers) {
			var schemeName = $"Header:{headerName}";

			// Skip if already registered (e.g., from static config)
			if (schemeRegistry.HeaderSchemes.ContainsKey(headerName)) {
				continue;
			}

			// Register the scheme
			schemeRegistry.RegisterHeaderScheme(headerName, schemeName);

			// Register the authentication handler for this scheme
			authBuilder.AddScheme<ApiKeyAuthenticationOptions, ApiKeyAuthenticationHandler>(
				schemeName,
				options => { options.HeaderName = headerName; });
		}
	}

	private static void ReplaceResolverWithComposite<TResolver>(
		IServiceCollection services,
		DynamicApiKeyOptions options)
		where TResolver : class, IApiKeyClientResolver {

		// Remove any existing IApiKeyClientResolver registration
		var existingDescriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(IApiKeyClientResolver));
		if (existingDescriptor is not null) {
			services.Remove(existingDescriptor);
		}

		// Register composite resolver: config first, then dynamic
		services.AddSingleton<IApiKeyClientResolver>(sp => {
			var resolvers = new List<IApiKeyClientResolver>();

			// 1. Configuration-based resolver first (fast, in-memory)
			var registry = sp.GetService<ApiKeyClientRegistry>();
			if (registry is not null && registry.RegisteredHeaders.Count > 0) {
				var configResolver = new ConfigurationApiKeyClientResolver(
					registry,
					sp.GetRequiredService<IApiKeyValidator>(),
					sp.GetRequiredService<IOptions<ApiKeyValidationOptions>>(),
					sp.GetRequiredService<ILogger<ConfigurationApiKeyClientResolver>>());
				resolvers.Add(configResolver);
			}

			// 2. Dynamic resolver second
			IApiKeyClientResolver dynamicResolver = sp.GetRequiredService<TResolver>();

			// Wrap with caching if enabled
			if (options.CachingEnabled) {
				dynamicResolver = new CachingApiKeyClientResolver(
					dynamicResolver,
					sp.GetRequiredService<IMemoryCache>(),
					sp.GetRequiredService<IOptions<ApiKeyCachingOptions>>(),
					sp.GetRequiredService<ILogger<CachingApiKeyClientResolver>>());
			}
			resolvers.Add(dynamicResolver);

			// If only one resolver, return it directly (avoid composite overhead)
			if (resolvers.Count == 1) {
				return resolvers[0];
			}

			return new CompositeApiKeyClientResolver(
				resolvers,
				sp.GetRequiredService<ILogger<CompositeApiKeyClientResolver>>());
		});
	}
}
