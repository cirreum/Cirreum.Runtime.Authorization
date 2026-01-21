namespace Cirreum.Authorization;

using Cirreum.AuthorizationProvider.ApiKey;

/// <summary>
/// Options for configuring dynamic API key resolution.
/// </summary>
public sealed class DynamicApiKeyOptions {

	internal bool CachingEnabled { get; private set; }
	internal Action<ApiKeyCachingOptions>? CachingConfiguration { get; private set; }
	internal Action<ApiKeyValidationOptions>? ValidationConfiguration { get; private set; }

	/// <summary>
	/// Enables in-memory caching of resolution results.
	/// </summary>
	/// <param name="configure">Optional configuration for caching behavior.</param>
	/// <returns>The options instance for chaining.</returns>
	public DynamicApiKeyOptions WithCaching(Action<ApiKeyCachingOptions>? configure = null) {
		this.CachingEnabled = true;
		this.CachingConfiguration = configure;
		return this;
	}

	/// <summary>
	/// Configures validation options for API keys.
	/// </summary>
	/// <param name="configure">The validation configuration action.</param>
	/// <returns>The options instance for chaining.</returns>
	public DynamicApiKeyOptions ConfigureValidation(Action<ApiKeyValidationOptions> configure) {
		this.ValidationConfiguration = configure ?? throw new ArgumentNullException(nameof(configure));
		return this;
	}
}
