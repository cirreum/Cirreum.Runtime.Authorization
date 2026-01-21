namespace Cirreum.Authorization;

using Cirreum.Authorization.External;

/// <summary>
/// Options for configuring External (BYOID) authentication registration.
/// </summary>
public sealed class ExternalOptions {

	internal Action<ExternalAuthenticationOptions>? OptionsConfiguration { get; private set; }

	/// <summary>
	/// Configures External authentication options.
	/// </summary>
	/// <param name="configure">The configuration action.</param>
	/// <returns>The options instance for chaining.</returns>
	/// <example>
	/// <code>
	/// builder.AddAuthorization(auth => auth
	///     .AddExternal&lt;MyResolver&gt;(options => options
	///         .ConfigureOptions(o => {
	///             o.TenantIdentifierSource = TenantIdentifierSource.Header;
	///             o.TenantHeaderName = "X-Tenant-Id";
	///             o.ValidateTenantInPath = true;
	///         }))
	/// );
	/// </code>
	/// </example>
	public ExternalOptions ConfigureOptions(Action<ExternalAuthenticationOptions> configure) {
		this.OptionsConfiguration = configure ?? throw new ArgumentNullException(nameof(configure));
		return this;
	}

}
