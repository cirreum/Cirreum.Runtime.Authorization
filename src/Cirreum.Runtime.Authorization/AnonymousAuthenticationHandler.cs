namespace Cirreum.Authorization;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler that returns <see cref="AuthenticateResult.NoResult()"/>
/// for requests with no authentication indicators.
/// </summary>
/// <remarks>
/// This handler is used by the dynamic scheme selector when a request contains
/// no authentication credentials. Returning <see cref="AuthenticateResult.NoResult()"/>
/// signals that authentication was not attempted, allowing endpoints marked with
/// <c>[AllowAnonymous]</c> to proceed without triggering authentication failures.
/// </remarks>
public sealed class AnonymousAuthenticationHandler(
	IOptionsMonitor<AuthenticationSchemeOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder
) : AuthenticationHandler<AuthenticationSchemeOptions>(
		options,
		logger,
		encoder) {

	/// <inheritdoc/>
	protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
		return Task.FromResult(AuthenticateResult.NoResult());
	}

}
