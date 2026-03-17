namespace Cirreum.Authorization;

using Cirreum.AuthorizationProvider;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Adapts an <see cref="IApplicationUserResolver"/> to <see cref="IRoleResolver"/>,
/// bridging the Cirreum Core application user model with the authorization provider's
/// role resolution contract.
/// </summary>
/// <remarks>
/// <para>
/// When the resolver returns an <see cref="IApplicationUser"/>, the adapter caches
/// it in <see cref="HttpContext.Items"/> using <see cref="IApplicationUserResolver.CacheKey"/>
/// so that downstream components (e.g. <c>UserAccessor</c>) can retrieve it without
/// a redundant resolution call.
/// </para>
/// <para>
/// The adapter does not enforce <see cref="IApplicationUser.IsEnabled"/>; that is
/// the responsibility of downstream components (e.g. <c>UserAccessor</c>, <c>AppRouteView</c>)
/// which have the full application context to decide how to handle disabled users.
/// </para>
/// </remarks>
internal sealed class ApplicationUserRoleResolverAdapter(
	IApplicationUserResolver resolver,
	IHttpContextAccessor httpContextAccessor
) : IRoleResolver {

	/// <inheritdoc />
	public async Task<IReadOnlyList<string>?> ResolveRolesAsync(
		string externalUserId,
		CancellationToken cancellationToken = default) {

		var applicationUser = await resolver.ResolveAsync(externalUserId, cancellationToken);

		// Cache the resolved application user for downstream components.
		if (applicationUser is not null && httpContextAccessor.HttpContext is { } context) {
			context.Items[IApplicationUserResolver.CacheKey] = applicationUser;
		}

		return applicationUser?.Roles;
	}

}
