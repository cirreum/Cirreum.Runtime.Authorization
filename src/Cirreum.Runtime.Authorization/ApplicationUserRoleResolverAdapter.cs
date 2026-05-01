namespace Cirreum.Authorization;

using Cirreum.AuthorizationProvider;
using Cirreum.Security;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Adapts <see cref="IApplicationUserResolver"/> to <see cref="IRoleResolver"/>,
/// bridging the Cirreum Core application user model with the authorization provider's
/// role resolution contract.
/// </summary>
/// <remarks>
/// <para>
/// In multi-IdP server hosts, multiple <see cref="IApplicationUserResolver"/> implementations
/// may be registered — one per scheme. The adapter dispatches to the resolver whose
/// <see cref="IApplicationUserResolver.Scheme"/> matches the request's authenticated scheme
/// (read from <see cref="AuthenticationContextKeys.AuthenticatedScheme"/> on
/// <see cref="HttpContext.Items"/>), falling back to the resolver whose <c>Scheme</c> is
/// <see langword="null"/> when no match is found. When no resolver matches and no fallback
/// is registered, role resolution is skipped — the correct behavior for operator/machine-track
/// callers that have no application user record.
/// </para>
/// <para>
/// When a resolver returns an <see cref="IApplicationUser"/>, the adapter caches it in
/// <see cref="HttpContext.Items"/> using <see cref="AuthenticationContextKeys.ApplicationUserCache"/>
/// so downstream components (e.g. <c>UserAccessor</c>) can retrieve it without a redundant call.
/// </para>
/// <para>
/// The adapter does not enforce <see cref="IApplicationUser.IsEnabled"/>; that is the
/// responsibility of downstream components (e.g. <c>UserAccessor</c>, <c>AppRouteView</c>)
/// which have the full application context to decide how to handle disabled users.
/// </para>
/// </remarks>
internal sealed class ApplicationUserRoleResolverAdapter(
	IEnumerable<IApplicationUserResolver> resolvers,
	IHttpContextAccessor httpContextAccessor
) : IRoleResolver {

	/// <inheritdoc />
	public async Task<IReadOnlyList<string>?> ResolveRolesAsync(
		string externalUserId,
		CancellationToken cancellationToken = default) {

		var context = httpContextAccessor.HttpContext;

		// Cache hit: an earlier consumer (custom middleware, test harness, or a
		// pre-warmed context) already resolved the application user. Skip the
		// resolver call and return the cached user's roles. The adapter remains
		// the canonical writer of the cache on miss; this read is symmetric with
		// UserAccessor's hot path.
		if (context is not null
			&& context.Items.TryGetValue(AuthenticationContextKeys.ApplicationUserCache, out var cached)
			&& cached is IApplicationUser cachedUser) {
			return cachedUser.Roles;
		}

		var scheme = context?.Items[AuthenticationContextKeys.AuthenticatedScheme] as string;

		var resolver = resolvers.FirstOrDefault(r => r.Scheme == scheme)
					?? resolvers.FirstOrDefault(r => r.Scheme is null);

		if (resolver is null) {
			return null;
		}

		var applicationUser = await resolver.ResolveAsync(externalUserId, cancellationToken);

		// Cache the resolved application user for downstream components.
		if (applicationUser is not null && context is not null) {
			context.Items[AuthenticationContextKeys.ApplicationUserCache] = applicationUser;
		}

		return applicationUser?.Roles;
	}

}
