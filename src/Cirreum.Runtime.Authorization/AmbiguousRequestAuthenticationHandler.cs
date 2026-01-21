namespace Cirreum.Authorization;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using System.Text.Encodings.Web;

/// <summary>
/// Authentication handler that always rejects requests with a 401 status.
/// Used when the dynamic scheme selector cannot determine the appropriate handler.
/// </summary>
/// <remarks>
/// <para>
/// This handler is used by the dynamic scheme selector in two scenarios:
/// </para>
/// <list type="number">
///   <item>
///     <description>
///     <b>Conflicting indicators</b> - Request contains multiple authentication
///     indicators (e.g., both API key header and tenant slug header). Rather than
///     guessing which scheme to use, the request is rejected.
///     </description>
///   </item>
///   <item>
///     <description>
///     <b>No matching scheme</b> - Request has authentication indicators (e.g.,
///     Bearer token) but no configured scheme can handle them (e.g., unrecognized
///     audience). Rather than silently falling back to an unrelated scheme, the
///     request is rejected.
///     </description>
///   </item>
/// </list>
/// </remarks>
public sealed class AmbiguousRequestAuthenticationHandler(
	IOptionsMonitor<AmbiguousRequestAuthenticationOptions> options,
	ILoggerFactory logger,
	UrlEncoder encoder
) : AuthenticationHandler<AmbiguousRequestAuthenticationOptions>(
		options,
		logger,
		encoder) {

	/// <inheritdoc/>
	protected override Task<AuthenticateResult> HandleAuthenticateAsync() {
		this.Logger.LogWarning(
			"Request rejected: unable to determine authentication scheme. " +
			"This may be due to conflicting authentication headers or " +
			"credentials that don't match any configured provider.");

		return Task.FromResult(
			AuthenticateResult.Fail(this.Options.FailureMessage));
	}

}