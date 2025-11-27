using JwtAuthentication.Identity.Models;
using JwtAuthentication.Shared;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JwtAuthentication.Services;

public class TokenProvider(UserManager<ApplicationUser> userManager,IOptionsMonitor<JwtConfiguration> options)
{
    public async Task<string> GenerateAcessTokenAsync(ApplicationUser user)
    {
        // Token generation logic goes here
        var roles = await userManager.GetRolesAsync(user);
        var singingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(options.CurrentValue.SecretKey)); // sign the token
        var credentials = new SigningCredentials(singingKey, SecurityAlgorithms.HmacSha256);
        // Collection Expressions 
        List<Claim> claims =
         [
            new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, user.Id),
            new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Name, user.UserName!),
            ..roles.Select(role => new Claim(ClaimTypes.Role, role)) // spread operator — it inserts items from another collection.
         ];
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(options.CurrentValue.ExpirationInMinutes),
            SigningCredentials = credentials,
            Issuer = options.CurrentValue.Issuer,
            Audience = options.CurrentValue.Audience,
        };

        var tokenHandler = new JsonWebTokenHandler();
        string accessToken = tokenHandler.CreateToken(tokenDescriptor);
        return accessToken;
    }
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}
