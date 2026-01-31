namespace Cirreum.Authorization;

/// <summary>
/// Defines authentication scheme names used by the Cirreum authorization system.
/// </summary>
public static class AuthorizationSchemes {

	/// <summary>
	/// The dynamic authentication scheme that automatically routes requests
	/// to the appropriate handler based on request characteristics.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This scheme examines request headers and tokens to determine which
	/// authentication handler should process the request:
	/// </para>
	/// <list type="bullet">
	///   <item>API key headers → API Key handler</item>
	///   <item>Signed request headers → Signed Request handler</item>
	///   <item>Tenant identifier + Bearer token → External (BYOID) handler</item>
	///   <item>Bearer token with recognized audience → Entra handler</item>
	///   <item>No match → Request rejected</item>
	/// </list>
	/// <para>
	/// Policies using this scheme accept authentication from any configured provider,
	/// with authorization determined by role claims. Use this when you want a policy
	/// that works across multiple authentication methods.
	/// </para>
	/// </remarks>
	public const string Dynamic = "DynamicScheme";

	/// <summary>
	/// The authentication scheme used when the dynamic selector cannot determine
	/// the appropriate handler due to conflicting or unrecognized credentials.
	/// </summary>
	/// <remarks>
	/// <para>
	/// This scheme is selected in two scenarios:
	/// </para>
	/// <list type="bullet">
	///   <item>
	///     <b>Conflicting indicators</b> - Request contains multiple authentication
	///     indicators (e.g., both API key header and tenant slug header)
	///   </item>
	///   <item>
	///     <b>No matching scheme</b> - Request has authentication indicators but no
	///     configured scheme can handle them (e.g., unrecognized JWT audience)
	///   </item>
	/// </list>
	/// <para>
	/// Requests routed to this scheme are always rejected with a 401 status.
	/// This fail-closed behavior prevents credentials from being evaluated by
	/// an unrelated handler.
	/// </para>
	/// </remarks>
	public const string Ambiguous = "AmbiguousRequest";

	/// <summary>
	/// The authentication scheme used when no authentication indicators are present.
	/// </summary>
	/// <remarks>
	/// Returns <see cref="Microsoft.AspNetCore.Authentication.AuthenticateResult.NoResult()"/>,
	/// allowing <c>[AllowAnonymous]</c> endpoints to proceed without authentication failure.
	/// </remarks>
	public const string Anonymous = "Anonymous";

}
