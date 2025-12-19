namespace Cirreum.AuthorizationProvider.SignedRequest;

/// <summary>
/// Options for configuring signed request authentication registration.
/// </summary>
public sealed class SignedRequestOptions {

	/// <summary>
	/// Gets or sets the authentication scheme name.
	/// Default is "SignedRequest".
	/// </summary>
	public string SchemeName { get; set; } = "SignedRequest";

	internal Action<SignatureValidationOptions>? ValidationConfiguration { get; private set; }

	/// <summary>
	/// Configures signature validation options.
	/// </summary>
	/// <param name="configure">The configuration action.</param>
	/// <returns>The options instance for chaining.</returns>
	public SignedRequestOptions ConfigureValidation(Action<SignatureValidationOptions> configure) {
		this.ValidationConfiguration = configure ?? throw new ArgumentNullException(nameof(configure));
		return this;
	}

	/// <summary>
	/// Sets the timestamp tolerance (how old a request can be).
	/// </summary>
	/// <param name="tolerance">The maximum age of requests.</param>
	/// <returns>The options instance for chaining.</returns>
	public SignedRequestOptions WithTimestampTolerance(TimeSpan tolerance) {
		this.ValidationConfiguration = opts => opts.TimestampTolerance = tolerance;
		return this;
	}

}