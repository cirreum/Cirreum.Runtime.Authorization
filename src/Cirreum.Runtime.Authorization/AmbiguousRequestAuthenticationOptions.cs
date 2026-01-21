namespace Cirreum.Authorization;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Options for the <see cref="AmbiguousRequestAuthenticationHandler"/>.
/// </summary>
public sealed class AmbiguousRequestAuthenticationOptions : AuthenticationSchemeOptions {

	/// <summary>
	/// The message returned when authentication fails.
	/// </summary>
	public string FailureMessage { get; set; } =
		"Unable to determine authentication method. " +
		"Verify your credentials match a configured authentication provider.";

}