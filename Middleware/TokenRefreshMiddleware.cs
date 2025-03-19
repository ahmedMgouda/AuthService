using Microsoft.Extensions.Caching.Memory;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using AuthService.Data;
using System.IdentityModel.Tokens.Jwt;
using AuthService.Authorization;
using Microsoft.Extensions.Options;

namespace AuthService.Middleware
{

    /// <summary>
    /// Middleware that checks if the user's claims version has changed.
    /// If the claims version is outdated, it forces a token refresh.
    /// </summary>
    public class TokenRefreshMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IMemoryCache _memoryCache;
        private readonly ILogger<TokenRefreshMiddleware> _logger;
        private readonly IServiceScopeFactory _scopeFactory;
        private readonly TimeSpan _cacheDuration;

        public TokenRefreshMiddleware(
            RequestDelegate next,
            IMemoryCache memoryCache,
            ILogger<TokenRefreshMiddleware> logger,
            IServiceScopeFactory scopeFactory,
            IOptions<CacheSettings> cacheSettings)
        {
            _next = next;
            _memoryCache = memoryCache;
            _logger = logger;
            _scopeFactory = scopeFactory;
            _cacheDuration = TimeSpan.FromHours(cacheSettings.Value.UserClaimsCacheDurationHours);
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                if (!context.User.Identity?.IsAuthenticated ?? true)
                {
                    await _next(context);
                    return;
                }

                if (!ExtractUserId(context.User, out int userId))
                {
                    _logger.LogWarning("Missing or invalid user ID in claims.");
                    ForceTokenRefresh(context, "Invalid claims.");
                    return;
                }

                if (!ExtractClaimsVersion(context.User, out Guid tokenClaimVersion))
                {
                    _logger.LogWarning("User {UserId} is missing a valid claims version.", userId);
                    ForceTokenRefresh(context, "Invalid claims.");
                    return;
                }

                var cacheKey = AuthConstants.UserClaimsVersion(userId);

                if (!_memoryCache.TryGetValue(cacheKey, out Guid cachedClaimVersion))
                {
                    cachedClaimVersion = await FetchLatestClaimsVersion(userId);

                    // Enforce ClaimsVersion existence
                    if (cachedClaimVersion == Guid.Empty)
                    {
                        _logger.LogWarning("User {UserId} does not have a claims version.", userId);
                        ForceTokenRefresh(context, "User does not have a claims version.");
                        return;
                    }

                    _memoryCache.Set(cacheKey, cachedClaimVersion, _cacheDuration);
                }

                if (tokenClaimVersion != cachedClaimVersion)
                {
                    _logger.LogWarning("User {UserId} has an outdated claims version. Expected: {ExpectedVersion}, Found: {UserVersion}.",
                        userId, cachedClaimVersion, tokenClaimVersion);

                    ForceTokenRefresh(context, "Outdated claims version.");
                    return;
                }

                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error in TokenRefreshMiddleware for request: {RequestPath}", context.Request.Path);
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            }
        }

        private async Task<Guid> FetchLatestClaimsVersion(int userId)
        {
            try
            {
                using var scope = _scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

                return await dbContext.Users
                    .AsNoTracking()
                    .Where(u => u.Id == userId)
                    .Select(u => u.ClaimsVersion)
                    .SingleOrDefaultAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Database error while fetching claims version for User {UserId}.", userId);
                return Guid.Empty;
            }
        }

        private static void ForceTokenRefresh(HttpContext context, string message)
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Headers["X-Token-Refresh"] = "true";

            var response = new { error = "Unauthorized", message };
            context.Response.ContentType = "application/json";
            context.Response.WriteAsJsonAsync(response);
        }

        private static bool ExtractUserId(ClaimsPrincipal user, out int userId)
        {
            var userIdClaim = user.FindFirstValue(JwtRegisteredClaimNames.Sub)
                               ?? user.FindFirstValue(ClaimTypes.NameIdentifier);

            return int.TryParse(userIdClaim, out userId);
        }

        private static bool ExtractClaimsVersion(ClaimsPrincipal user, out Guid claimsVersion)
        {
            return Guid.TryParse(user.FindFirstValue(AuthConstants.ClaimsVersion), out claimsVersion);
        }
    }
}
