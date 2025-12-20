namespace Cirreum.AuthorizationProvider.SignedRequest;

/// <summary>
/// Options for configuring signed request authentication registration.
/// </summary>
public sealed class SignedRequestOptions {

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

}