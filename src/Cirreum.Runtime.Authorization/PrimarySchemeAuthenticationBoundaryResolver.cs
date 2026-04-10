namespace Cirreum.Authorization;

using Cirreum.Security;

/// <summary>
/// Resolves <see cref="AuthenticationBoundary"/> by comparing the caller's authentication
/// scheme against the configured <c>Cirreum:Authorization:PrimaryScheme</c>.
/// </summary>
/// <remarks>
/// <para>
/// Callers who authenticate via the primary scheme are classified as
/// <see cref="AuthenticationBoundary.Global"/> (operator staff). All other authenticated
/// schemes — External (BYOID), API keys, signed requests, secondary Entra instances —
/// are classified as <see cref="AuthenticationBoundary.Tenant"/>.
/// </para>
/// <para>
/// This resolver is registered automatically by <c>HostingExtensions.AddAuthorization</c>
/// before Core's default resolver, which treats all callers as Global.
/// </para>
/// </remarks>
sealed class PrimarySchemeAuthenticationBoundaryResolver(string primaryScheme)
	: IAuthenticationBoundaryResolver {

	/// <inheritdoc/>
	public AuthenticationBoundary Resolve(IUserState userState, string? authenticationScheme) {
		if (!userState.IsAuthenticated) {
			return AuthenticationBoundary.None;
		}
		return string.Equals(authenticationScheme, primaryScheme, StringComparison.OrdinalIgnoreCase)
			? AuthenticationBoundary.Global
			: AuthenticationBoundary.Tenant;
	}
}
