using Microsoft.AspNetCore.Authorization;

namespace AuthService.Authorization
{
    /// <summary>
    /// Custom authorization handler enforcing permission-based policies.
    /// </summary>
    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirement>
    {
        private readonly ILogger<PermissionAuthorizationHandler> _logger;

        public PermissionAuthorizationHandler(ILogger<PermissionAuthorizationHandler> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Checks if the authenticated user possesses the required permission.
        /// Grants access if the permission exists; otherwise, logs a warning.
        /// </summary>
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            var user = context.User;

            if (user.Identity?.IsAuthenticated != true)
            {
                _logger.LogWarning("Authorization failed: Unauthenticated user.");
                return Task.CompletedTask;
            }

            var userName = user.Identity.Name ?? "Unknown User";

            var userPermissions = user.FindAll("Permission")
                                      .Select(c => c.Value)
                                      .ToHashSet(StringComparer.OrdinalIgnoreCase);

            if (userPermissions.Contains(requirement.Permission))
            {
                _logger.LogInformation("Authorization succeeded: {@User} has permission '{@Permission}'.", userName, requirement.Permission);
                context.Succeed(requirement);
            }
            else
            {
                _logger.LogWarning("Authorization failed: {@User} lacks required permission '{@Permission}'.", userName, requirement.Permission);
            }

            return Task.CompletedTask;
        }
    }
}
