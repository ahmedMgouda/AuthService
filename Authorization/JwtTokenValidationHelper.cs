using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace AuthService.Authorization
{
    public static class JwtTokenValidationHelper
    {
        public static TokenValidationParameters GetValidationParameters(JwtOptions jwtOptions)
        {
            return new TokenValidationParameters
            {
                ValidateIssuer = !string.IsNullOrWhiteSpace(jwtOptions.Issuer),
                ValidateAudience = !string.IsNullOrWhiteSpace(jwtOptions.Audience),
                ValidIssuer = jwtOptions.Issuer,
                ValidAudience = jwtOptions.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Secret)),
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };
        }
    }

}
