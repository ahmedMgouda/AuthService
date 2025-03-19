using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthService.Authorization;
using AuthService.Data;
using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthService.Services
{
    public class JwtService
    {
        private readonly JwtOptions _jwtOptions;
        private readonly ILogger<JwtService> _logger;
        private readonly IMemoryCache _memoryCache;
        private readonly AuthDbContext _dbContext;
        private readonly JwtSecurityTokenHandler _tokenHandler;
        private readonly TokenValidationParameters _tokenValidationParams;

        public JwtService(
            IOptions<JwtOptions> jwtOptions,
            ILogger<JwtService> logger,
            IMemoryCache memoryCache,
            AuthDbContext dbContext,
            JwtSecurityTokenHandler tokenHandler)
        {
            _jwtOptions = jwtOptions.Value;
            _dbContext = dbContext;
            _logger = logger;
            _memoryCache = memoryCache;
            _tokenHandler = tokenHandler;
            _tokenValidationParams = JwtTokenValidationHelper.GetValidationParameters(_jwtOptions);
        }

        /// <summary>
        /// Generate JWT Token
        /// </summary>
        public async Task<string> GenerateJwtAsync(User user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            _logger.LogInformation("Generating JWT for user: {UserId}", user.Id);

            var rolesAndPermissions = await _dbContext.UserRoles
              .Where(ur => ur.UserId == user.Id)
              .SelectMany(ur => ur.Role.RolePermissions)
              .Select(rp => new { rp.Role.Name, Permission = rp.Permission.Name })
              .Distinct()
              .ToListAsync();

            var claims = new List<Claim>
        {
            new(AuthConstants.Sub, user.Id.ToString()),
            new(AuthConstants.Email, user.Email),
            new(AuthConstants.Jti, Guid.NewGuid().ToString()),
            new(AuthConstants.ClaimsVersion, user.ClaimsVersion.ToString())
        };

            claims.AddRange(rolesAndPermissions.Select(rp => new Claim(AuthConstants.Role, rp.Name)).Distinct());
            claims.AddRange(rolesAndPermissions.Select(rp => new Claim(AuthConstants.Permission, rp.Name)).Distinct());

            return GenerateToken(claims, _jwtOptions.AccessTokenExpirationMinutes);
        }

        /// <summary>
        /// Generate Refresh Token
        /// </summary>
        public async Task<string> GenerateRefreshTokenAsync(User user, CancellationToken cancellationToken = default)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var refreshTokenId = Guid.NewGuid();

            var claims = new List<Claim>
            {
                new(AuthConstants.Sub, user.Id.ToString()),
                new(AuthConstants.RefreshTokenId, refreshTokenId.ToString())
            };

            var refreshTokenString = GenerateToken(claims, _jwtOptions.RefreshTokenExpirationDays * 24 * 60);

            _dbContext.RefreshTokens.Add(new RefreshToken
            {
                Id = refreshTokenId,
                UserId = user.Id,
                ExpirationDate = DateTime.UtcNow.AddDays(_jwtOptions.RefreshTokenExpirationDays),
                CreatedAt = DateTime.UtcNow
            });

            await _dbContext.SaveChangesAsync(cancellationToken);

            return refreshTokenString;
        }

        /// <summary>
        /// Validate Refresh Token
        /// </summary>
        public async Task<User?> ValidateRefreshTokenAsync(string refreshToken, CancellationToken cancellationToken = default)
        {
            try
            {
                var principal = _tokenHandler.ValidateToken(refreshToken, _tokenValidationParams, out _);
                var refreshTokenIdStr = principal.Claims.FirstOrDefault(c => c.Type == AuthConstants.RefreshTokenId)?.Value;
                var userIdStr = principal.Claims.FirstOrDefault(c => c.Type == AuthConstants.Sub)?.Value
                                ?? principal.Claims.FirstOrDefault(c => c.Type == AuthConstants.NameIdentifier)?.Value;

                if (!Guid.TryParse(refreshTokenIdStr, out var refreshTokenId) || !int.TryParse(userIdStr, out var userId))
                {
                    _logger.LogWarning("Invalid refresh token structure.");
                    return null;
                }


                var tokenData = await _dbContext.RefreshTokens
                   .Include(rt => rt.User)
                   .Where(rt => rt.Id == refreshTokenId && rt.UserId == userId && !rt.IsRevoked && rt.ExpirationDate > DateTime.UtcNow)
                   .Select(rt => new { rt.User, rt.Id })
                   .AsNoTracking()
                   .FirstOrDefaultAsync(cancellationToken);

                if (tokenData == null)
                {
                    _logger.LogWarning("Refresh token is invalid, revoked, or expired.");
                    return null;
                }

                await RevokeRefreshTokenAsync(tokenData.Id, cancellationToken);
                return tokenData.User;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating refresh token.");
                return null;
            }
        }

        public async Task RevokeRefreshTokenAsync(Guid refreshTokenId, CancellationToken cancellationToken = default)
        {
            var refreshToken = await _dbContext.RefreshTokens.FindAsync([refreshTokenId], cancellationToken);
            if (refreshToken == null) return;

            refreshToken.IsRevoked = true;
            refreshToken.RevokedAt = DateTime.UtcNow;
            await _dbContext.SaveChangesAsync(cancellationToken);
        }

        public async Task<User?> UpdateClaimsVersion(int userId)
        {
            var user = await _dbContext.Users.FindAsync(userId);
            if (user == null) return null;

            user.ClaimsVersion = Guid.NewGuid();
            await _dbContext.SaveChangesAsync();

            if (_memoryCache.TryGetValue(AuthConstants.UserClaimsVersion(userId), out _))
            {
                _memoryCache.Remove(AuthConstants.UserClaimsVersion(userId));
            }

            return user;
        }

        private string GenerateToken(IEnumerable<Claim> claims, int expirationMinutes)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                _jwtOptions.Issuer,
                _jwtOptions.Audience,
                claims,
                expires: DateTime.UtcNow.AddMinutes(expirationMinutes),
                signingCredentials: creds
            );

            return _tokenHandler.WriteToken(token);
        }
    }
}
