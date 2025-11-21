using ErrorOr;
using FluentValidation;
using JwtAuthentication.DTO;
using JwtAuthentication.Identity;
using JwtAuthentication.Identity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace JwtAuthentication.Services;

public class UserService(UserDbContext context, UserManager<ApplicationUser> userManager,
   IValidator<UserRegisterationRequest> registerValidator, IConfiguration configuration, IValidator<LoginUserRequest> loginValidator) : IUserService
{
    public async Task<ErrorOr<string>> LoginUserAsync(LoginUserRequest request)
    {
        var validationResult = await loginValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            // Return all validation messages
            return Error.Validation("LoginUser.InvalidRequest", string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage)));
        }
        var user = await userManager.FindByNameAsync(request.UserName);
        if (user is null || !await userManager.CheckPasswordAsync(user, request.Password))
        {
            return Error.NotFound("Invalid UserName Or Password ");
        }
        var roles = await userManager.GetRolesAsync(user);
        var singingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:SecretKey"]!)); // sign the token
        var credentials = new SigningCredentials(singingKey, SecurityAlgorithms.HmacSha256);
        // Collection Expressions 
        List<Claim> claims =
         [
            new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Sub, user.Id),
            new(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Nickname, user.UserName!),
            ..roles.Select(role => new Claim(ClaimTypes.Role, role)) // spread operator — it inserts items from another collection.
         ];
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(configuration.GetValue<int>("Jwt:ExpirationInMinutes")),
            SigningCredentials = credentials,
            Issuer = configuration["Jwt:Issuer"],
            Audience = configuration["Jwt:Audience"]
        }; 

        var tokenHandler = new JsonWebTokenHandler();
        string accessToken = tokenHandler.CreateToken(tokenDescriptor);
        return accessToken;
    }

    public async Task<string> RegisterUserAsync(UserRegisterationRequest request)
    {
        var validationResult = await registerValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            // Return all validation messages
            return string.Join(", ", validationResult.Errors.Select(e => e.ErrorMessage));
        }
        var user = new ApplicationUser()
        {
            FirstName = request.FirstName,
            LastName = request.LastName,
            UserName = request.UserName,
            PhoneNumber = request.PhoneNumber
        };
        var result = await userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
        {
            return string.Join(", ", result.Errors.Select(e => e.Description));
        }

        return string.Empty;   // success

    }
}
