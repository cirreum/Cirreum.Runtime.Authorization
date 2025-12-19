namespace Microsoft.AspNetCore.Authorization;

using Cirreum.AuthorizationProvider;
using Cirreum.AuthorizationProvider.SignedRequest;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

/// <summary>
/// Extension methods for configuring signed request authorization on <see cref="AuthorizationBuilder"/>.
/// </summary>
public static class SignedRequestAuthorizationBuilderExtensions {

	private class SignedRequestMarker { }

	/// <summary>
	/// Adds signed request authentication using a custom resolver (e.g., database-backed).
	/// </summary>
	/// <typeparam name="TResolver">
	/// The resolver type that implements <see cref="ISignedRequestClientResolver"/>.
	/// </typeparam>
	/// <param name="builder">The authorization builder.</param>
	/// <param name="configure">Optional configuration for signature validation.</param>
	/// <returns>The authorization builder for chaining.</returns>
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
	/// Use the scheme "SignedRequest" in your policies:
	/// <c>.AddAuthenticationSchemes("SignedRequest")</c>
	/// </para>
	/// </remarks>
	/// <example>
	/// <code>
	/// builder
	///     .AddAuthorization()
	///     .AddSignedRequestAuth&lt;DatabaseSignedRequestResolver&gt;(options => {
	///         options.TimestampTolerance = TimeSpan.FromMinutes(2);
	///     })
	///     .AddPolicy("PartnerAccess", policy => {
	///         policy
	///             .AddAuthenticationSchemes("SignedRequest")
	///             .RequireAuthenticatedUser()
	///             .RequireRole("partner");
	///     });
	/// </code>
	/// </example>
	public static AuthorizationBuilder AddSignedRequestAuth<TResolver>(
		this AuthorizationBuilder builder,
		Action<SignedRequestOptions>? configure = null)
		where TResolver : class, ISignedRequestClientResolver {

		var services = builder.Services;

		// Check if already registered
		if (services.IsMarkerTypeRegistered<SignedRequestMarker>()) {
			return builder;
		}
		services.MarkTypeAsRegistered<SignedRequestMarker>();

		// Build options
		var options = new SignedRequestOptions();
		configure?.Invoke(options);

		// Configure validation options
		if (options.ValidationConfiguration is not null) {
			services.Configure(options.ValidationConfiguration);
		}
		else {
			// Register default options
			services.TryAddSingleton(Microsoft.Extensions.Options.Options.Create(new SignatureValidationOptions()));
		}

		// Register core services
		services.TryAddSingleton<ISignatureValidator, DefaultSignatureValidator>();
		services.TryAddSingleton<ISignatureValidationEvents>(NullSignatureValidationEvents.Instance);

		// Register the custom resolver
		services.TryAddScoped<TResolver>();
		services.TryAddScoped<ISignedRequestClientResolver>(sp => sp.GetRequiredService<TResolver>());

		// Register authentication handler
		RegisterSignedRequestScheme(services, options.SchemeName);

		return builder;
	}

	/// <summary>
	/// Adds a custom implementation of <see cref="ISignatureValidationEvents"/> for
	/// rate limiting, alerting, and other security controls.
	/// </summary>
	/// <typeparam name="TEvents">The events implementation type.</typeparam>
	/// <param name="builder">The authorization builder.</param>
	/// <returns>The authorization builder for chaining.</returns>
	public static AuthorizationBuilder AddSignatureValidationEvents<TEvents>(
		this AuthorizationBuilder builder)
		where TEvents : class, ISignatureValidationEvents {

		// Remove the null implementation if registered
		var existing = builder.Services.FirstOrDefault(d =>
			d.ServiceType == typeof(ISignatureValidationEvents));
		if (existing is not null) {
			builder.Services.Remove(existing);
		}

		builder.Services.AddScoped<ISignatureValidationEvents, TEvents>();
		return builder;
	}

	private static void RegisterSignedRequestScheme(IServiceCollection services, string schemeName) {
		// Get the authentication builder that was stored during AddAuthorization
		var authBuilderDescriptor = services.FirstOrDefault(d =>
			d.ServiceType == typeof(AuthenticationBuilder) &&
			d.ImplementationInstance is not null);

		if (authBuilderDescriptor?.ImplementationInstance is not AuthenticationBuilder authBuilder) {
			throw new InvalidOperationException(
				"AddSignedRequestAuth must be called after AddAuthorization. " +
				"Ensure you call builder.AddAuthorization() first.");
		}

		// Register the authentication handler
		authBuilder.AddScheme<SignedRequestAuthenticationOptions, SignedRequestAuthenticationHandler>(
			schemeName,
			options => { options.SchemeName = schemeName; });

		// Register the scheme in the registry for dynamic selection
		var schemeRegistry = services.GetAuthorizationSchemeRegistry();
		schemeRegistry.RegisterCustomScheme(schemeName);
	}
}
