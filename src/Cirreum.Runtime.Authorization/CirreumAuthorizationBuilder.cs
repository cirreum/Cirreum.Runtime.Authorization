namespace Cirreum.Authorization;

using Cirreum.Authorization.External;
using Cirreum.AuthorizationProvider;
using Cirreum.AuthorizationProvider.ApiKey;
using Cirreum.AuthorizationProvider.SignedRequest;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Builder for configuring Cirreum authentication providers within the authorization system.
/// </summary>
/// <remarks>
/// <para>
/// This builder is accessed via the <c>AddAuthorization</c> extension method's lambda parameter:
/// </para>
/// <code>
/// builder.AddAuthorization(auth => auth
///     .AddSignedRequest&lt;MyResolver&gt;()
///     .AddDynamicApiKeys&lt;MyResolver&gt;(["X-Api-Key"])
///     .AddExternal&lt;MyResolver&gt;()
/// );
/// </code>
/// <para>
/// The builder provides access to authentication schemes that require custom resolvers
/// for database-backed or dynamic credential validation.
/// </para>
/// </remarks>
public sealed class CirreumAuthorizationBuilder {

	private class SignedRequestMarker { }
	private class ApiKeyDynamicMarker { }
	private class ExternalResolverMarker { }

	/// <summary>
	/// Gets the service collection for dependency registration.
	/// </summary>
	internal IServiceCollection Services { get; }

	/// <summary>
	/// Gets the underlying ASP.NET Core authorization builder.
	/// </summary>
	internal AuthorizationBuilder AuthorizationBuilder { get; }

	/// <summary>
	/// Initializes a new instance of the <see cref="CirreumAuthorizationBuilder"/> class.
	/// </summary>
	/// <param name="services">The service collection.</param>
	/// <param name="authorizationBuilder">The ASP.NET Core authorization builder.</param>
	internal CirreumAuthorizationBuilder(
		IServiceCollection services,
		AuthorizationBuilder authorizationBuilder) {
		Services = services;
		AuthorizationBuilder = authorizationBuilder;
	}

	/// <summary>
	/// Adds signed request authentication using a custom resolver (e.g., database-backed).
	/// </summary>
	/// <typeparam name="TResolver">
	/// The resolver type that implements <see cref="ISignedRequestClientResolver"/>.
	/// </typeparam>
	/// <param name="configure">Optional configuration for signature validation.</param>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// This method registers the signed request authentication scheme for validating
	/// HMAC-signed requests from partners/customers.
	/// </para>
	/// <para>
	/// Partners send three headers:
	/// <list type="bullet">
	///   <item><c>X-Client-Id</c> - Public client identifier for database lookup</item>
	///   <item><c>X-Timestamp</c> - Unix timestamp for replay protection</item>
	///   <item><c>X-Signature</c> - HMAC signature in format "v1=hexstring"</item>
	/// </list>
	/// </para>
	/// <para>
	/// Use the scheme <see cref="SignedRequestDefaults.AuthenticationScheme"/> in your policies:
	/// <c>.AddAuthenticationSchemes(SignedRequestDefaults.AuthenticationScheme)</c>
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// builder.AddAuthorization(auth => auth
	///     .AddSignedRequest&lt;DatabaseSignedRequestResolver&gt;(options => {
	///         options.ConfigureValidation(v => v.TimestampTolerance = TimeSpan.FromMinutes(2));
	///     })
	/// )
	/// .AddPolicy("PartnerAccess", policy => {
	///     policy
	///         .AddAuthenticationSchemes(SignedRequestDefaults.AuthenticationScheme)
	///         .RequireAuthenticatedUser()
	///         .RequireRole("partner");
	/// });
	/// </code>
	/// </example>
	public CirreumAuthorizationBuilder AddSignedRequest<TResolver>(
		Action<SignedRequestOptions>? configure = null)
		where TResolver : class, ISignedRequestClientResolver {

		// Check if already registered
		if (Services.IsMarkerTypeRegistered<SignedRequestMarker>()) {
			return this;
		}
		Services.MarkTypeAsRegistered<SignedRequestMarker>();

		// Build options
		var options = new SignedRequestOptions();
		configure?.Invoke(options);

		// Configure validation options
		if (options.ValidationConfiguration is not null) {
			Services.Configure(options.ValidationConfiguration);
		} else {
			// Register default options
			Services.TryAddSingleton(Options.Create(new SignatureValidationOptions()));
		}

		// Register core services
		Services.TryAddSingleton<ISignatureValidator, DefaultSignatureValidator>();
		Services.TryAddSingleton<ISignatureValidationEvents>(NullSignatureValidationEvents.Instance);

		// Register the custom resolver
		Services.TryAddScoped<TResolver>();
		Services.TryAddScoped<ISignedRequestClientResolver>(sp => sp.GetRequiredService<TResolver>());

		// Register authentication handler
		RegisterSignedRequestScheme();

		return this;
	}

	/// <summary>
	/// Adds a custom implementation of <see cref="ISignatureValidationEvents"/> for
	/// rate limiting, alerting, and other security controls.
	/// </summary>
	/// <typeparam name="TEvents">The events implementation type.</typeparam>
	/// <returns>The builder for chaining.</returns>
	public CirreumAuthorizationBuilder AddSignatureValidationEvents<TEvents>()
		where TEvents : class, ISignatureValidationEvents {

		// Remove the null implementation if registered
		var existing = Services.FirstOrDefault(d =>
			d.ServiceType == typeof(ISignatureValidationEvents));
		if (existing is not null) {
			Services.Remove(existing);
		}

		Services.AddScoped<ISignatureValidationEvents, TEvents>();
		return this;
	}

	/// <summary>
	/// Adds dynamic API key resolution using a custom resolver (e.g., database-backed).
	/// </summary>
	/// <typeparam name="TResolver">
	/// The resolver type that implements <see cref="IApiKeyClientResolver"/>.
	/// </typeparam>
	/// <param name="headers">The HTTP header names that will contain API keys (e.g., "X-Api-Key").</param>
	/// <param name="configure">Optional configuration for caching and validation.</param>
	/// <returns>The builder for chaining.</returns>
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
	/// builder.AddAuthorization(auth => auth
	///     .AddDynamicApiKeys&lt;DatabaseApiKeyClientResolver&gt;(
	///         headers: ["X-Api-Key"],
	///         configure: options => {
	///             options.WithCaching(cache => {
	///                 cache.SuccessCacheDuration = TimeSpan.FromMinutes(5);
	///             });
	///         })
	/// )
	/// .AddPolicy("PartnerAccess", policy => {
	///     policy
	///         .AddAuthenticationSchemes("Header:X-Api-Key")
	///         .RequireAuthenticatedUser()
	///         .RequireRole("partner");
	/// });
	/// </code>
	/// </example>
	public CirreumAuthorizationBuilder AddDynamicApiKeys<TResolver>(
		string[] headers,
		Action<DynamicApiKeyOptions>? configure = null)
		where TResolver : class, IApiKeyClientResolver {

		ArgumentNullException.ThrowIfNull(headers);
		if (headers.Length == 0) {
			throw new ArgumentException("At least one header must be specified", nameof(headers));
		}

		// Check if already registered
		if (Services.IsMarkerTypeRegistered<ApiKeyDynamicMarker>()) {
			return this;
		}
		Services.MarkTypeAsRegistered<ApiKeyDynamicMarker>();

		// Build options
		var options = new DynamicApiKeyOptions();
		configure?.Invoke(options);

		// Apply validation configuration if provided
		if (options.ValidationConfiguration is not null) {
			Services.Configure(options.ValidationConfiguration);
		}

		// Apply caching configuration if provided
		if (options.CachingEnabled && options.CachingConfiguration is not null) {
			Services.Configure(options.CachingConfiguration);
		}

		// Register the custom resolver type
		Services.TryAddScoped<TResolver>();

		// Remove the default configuration-only resolver and replace with composite
		ReplaceResolverWithComposite<TResolver>(options);

		// Register authentication handlers for the specified headers
		RegisterDynamicHeaders(headers);

		return this;
	}

	/// <summary>
	/// Adds External (BYOID) authentication using a custom tenant resolver.
	/// </summary>
	/// <typeparam name="TResolver">
	/// The resolver type that implements <see cref="IExternalTenantResolver"/>.
	/// </typeparam>
	/// <param name="configure">Optional configuration for External authentication.</param>
	/// <returns>The builder for chaining.</returns>
	/// <remarks>
	/// <para>
	/// This method registers the tenant resolver for External (BYOID) authentication.
	/// The authentication handler and core services are registered via the
	/// <c>ExternalAuthorizationRegistrar</c> from appsettings.json configuration.
	/// </para>
	/// <para>
	/// The tenant resolver is called during authentication to determine which
	/// IdP configuration to use for validating the token. Implement
	/// <see cref="IExternalTenantResolver"/> to provide tenant configuration
	/// from your database or other backing store.
	/// </para>
	/// <para>
	/// Use the scheme <see cref="ExternalDefaults.AuthenticationScheme"/> in your policies:
	/// <c>.AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)</c>
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// builder.AddAuthorization(auth => auth
	///     .AddExternal&lt;DatabaseTenantResolver&gt;()
	/// )
	/// .AddPolicy("TenantAccess", policy => {
	///     policy
	///         .AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)
	///         .RequireAuthenticatedUser()
	///         .RequireRole("app:user");
	/// });
	/// </code>
	/// </example>
	/// <exception cref="InvalidOperationException">
	/// Thrown when External authentication is not configured in appsettings.json.
	/// </exception>
	public CirreumAuthorizationBuilder AddExternal<TResolver>(
		Action<ExternalOptions>? configure = null)
		where TResolver : class, IExternalTenantResolver {

		// Check if resolver is already registered
		if (Services.IsMarkerTypeRegistered<ExternalResolverMarker>()) {
			return this;
		}
		Services.MarkTypeAsRegistered<ExternalResolverMarker>();

		// Verify the External authentication handler was registered by the registrar
		var optionsDescriptor = Services.FirstOrDefault(d =>
			d.ServiceType == typeof(ExternalAuthenticationOptions))
			?? throw new InvalidOperationException(
				"AddExternal requires External authentication to be configured in appsettings.json. " +
				"Ensure the 'External' provider is configured under 'Authorization:Providers' with at least one instance.");

		// Apply configuration overrides if provided
		if (configure is not null) {
			var options = new ExternalOptions();
			configure(options);

			if (options.OptionsConfiguration is not null &&
				optionsDescriptor.ImplementationInstance is ExternalAuthenticationOptions existingOptions) {
				options.OptionsConfiguration(existingOptions);
			}
		}

		// Register the tenant resolver
		Services.TryAddScoped<TResolver>();
		Services.TryAddScoped<IExternalTenantResolver>(sp => sp.GetRequiredService<TResolver>());

		return this;
	}

	private void RegisterSignedRequestScheme() {

		// Get the authentication builder that was stored during AddAuthorization
		var authBuilderDescriptor = Services.FirstOrDefault(d =>
			d.ServiceType == typeof(AuthenticationBuilder) &&
			d.ImplementationInstance is not null);

		if (authBuilderDescriptor?.ImplementationInstance is not AuthenticationBuilder authBuilder) {
			throw new InvalidOperationException(
				"AddSignedRequest must be called within the AddAuthorization configuration. " +
				"Ensure you use: builder.AddAuthorization(auth => auth.AddSignedRequest<T>())");
		}

		// Register the authentication handler
		authBuilder.AddScheme<SignedRequestAuthenticationOptions, SignedRequestAuthenticationHandler>(
			authenticationScheme: SignedRequestDefaults.AuthenticationScheme, null, null);

		// Register the scheme in the registry for dynamic selection
		var schemeRegistry = Services.GetAuthorizationSchemeRegistry();
		schemeRegistry.RegisterCustomScheme(SignedRequestDefaults.AuthenticationScheme);

	}

	private void RegisterDynamicHeaders(string[] headers) {

		// Get the authentication builder that was stored during AddAuthorization
		var authBuilderDescriptor = Services.FirstOrDefault(d =>
			d.ServiceType == typeof(AuthenticationBuilder) &&
			d.ImplementationInstance is not null);

		if (authBuilderDescriptor?.ImplementationInstance is not AuthenticationBuilder authBuilder) {
			throw new InvalidOperationException(
				"AddDynamicApiKeys must be called within the AddAuthorization configuration. " +
				"Ensure you use: builder.AddAuthorization(auth => auth.AddDynamicApiKeys<T>(...))");
		}

		// Get the scheme registry
		var schemeRegistry = Services.GetAuthorizationSchemeRegistry();

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

	private void ReplaceResolverWithComposite<TResolver>(DynamicApiKeyOptions options)
		where TResolver : class, IApiKeyClientResolver {

		// Remove any existing IApiKeyClientResolver registration
		var existingDescriptor = Services.FirstOrDefault(d =>
			d.ServiceType == typeof(IApiKeyClientResolver));
		if (existingDescriptor is not null) {
			Services.Remove(existingDescriptor);
		}

		// Register composite resolver: config first, then dynamic
		Services.AddScoped(sp => {
			var resolvers = new List<IApiKeyClientResolver>();

			// 1. Configuration-based resolver first (fast, in-memory)
			var registry = sp.GetService<ApiKeyClientRegistry>();
			if (registry is not null && registry.RegisteredHeaders.Count > 0) {
				var configResolver = new ConfigurationApiKeyClientResolver(
					registry,
					sp.GetRequiredService<IApiKeyValidator>(),
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
