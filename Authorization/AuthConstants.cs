using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AuthService.Authorization
{
    public static class AuthConstants
    {
        public const string NameIdentifier = ClaimTypes.NameIdentifier;
        public const string Role = ClaimTypes.Role;
        public const string Sub = JwtRegisteredClaimNames.Sub;
        public const string Email = JwtRegisteredClaimNames.Email;
        public const string Jti = JwtRegisteredClaimNames.Jti;
        public const string ClaimsVersion = "claims_version";
        public const string RefreshTokenId = "refresh_token_id";
        public const string Permission = "permission";
        public static string UserClaimsVersion(int userId) => $"user_claims_version:{userId}";

    }

}
