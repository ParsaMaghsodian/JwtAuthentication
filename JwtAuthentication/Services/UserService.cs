using ErrorOr;
using FluentValidation;
using JwtAuthentication.DTO;
using JwtAuthentication.Identity;
using JwtAuthentication.Identity.Models;
using JwtAuthentication.Shared;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq.Expressions;
using System.Net.WebSockets;
using System.Security.Claims;
using System.Text;


namespace JwtAuthentication.Services;

public class UserService(UserDbContext context, UserManager<ApplicationUser> userManager,
   IValidator<UserRegisterationRequest> registerValidator, TokenProvider tokenProvider,
   IValidator<LoginUserRequest> loginValidator, IValidator<LoginUserWithRefreshTokenRequest> loginWithRefreshTokenValidator, IHttpContextAccessor httpContextAccessor) : IUserService
{
    private string? GetCurrentUserId()
    {
        var userIdString = httpContextAccessor.HttpContext?
            .User
            .FindFirstValue(ClaimTypes.NameIdentifier);
        return userIdString;
    }

    public async Task<ErrorOr<LoginUserResponse>> LoginUserAsync(LoginUserRequest request)
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
        string acessToken = await tokenProvider.GenerateAcessTokenAsync(user);
        string refreshToken = await GetOrCreateRefreshTokenAsync(user);

        return new LoginUserResponse(acessToken, refreshToken);
    }
    private async Task<string> GetOrCreateRefreshTokenAsync(ApplicationUser user)
    {
        var existingToken = await context.RefreshTokens
            .FirstOrDefaultAsync(r => r.UserId == user.Id);

        if (existingToken is null || existingToken.ExpiresOnUtc < DateTime.UtcNow)
        {
            // Create new or update expired refresh token
            if (existingToken is null)
            {
                existingToken = new RefreshToken
                {
                    Id = Guid.NewGuid(),
                    UserId = user.Id,
                    ExpiresOnUtc = DateTime.UtcNow.AddDays(7),
                    Token = tokenProvider.GenerateRefreshToken()
                };
                context.RefreshTokens.Add(existingToken);
            }
            else
            {
                existingToken.Token = tokenProvider.GenerateRefreshToken();
                existingToken.ExpiresOnUtc = DateTime.UtcNow.AddDays(7);
            }

            await context.SaveChangesAsync();
        }

        // Return the valid refresh token
        return existingToken.Token;
    }

    public async Task<ErrorOr<LoginUserWithRefreshTokenResponse>> LoginUserWithRefreshTokenAsync(LoginUserWithRefreshTokenRequest request)
    {
        var validationResult = await loginWithRefreshTokenValidator.ValidateAsync(request);
        if (!validationResult.IsValid)
        {
            return validationResult.Errors
        .Select(e => Error.Validation(
            code: e.PropertyName,
            description: e.ErrorMessage))
        .ToList();

        }
        RefreshToken? refreshToken = await context.RefreshTokens
             .Include(r => r.User)
             .FirstOrDefaultAsync(rt => rt.Token == request.RefreshToken);
        if (refreshToken is null || refreshToken.ExpiresOnUtc < DateTime.UtcNow)
        {
            return Error.NotFound("RefreshToken.Invalid", "The provided refresh token is invalid or has expired.");
        }

        string newAcessToken = await tokenProvider.GenerateAcessTokenAsync(refreshToken.User);
        string newRefreshTokenString = tokenProvider.GenerateRefreshToken();
        // Update the existing refresh token
        refreshToken.Token = newRefreshTokenString;
        refreshToken.ExpiresOnUtc = DateTime.UtcNow.AddDays(7);
        await context.SaveChangesAsync();
        return new LoginUserWithRefreshTokenResponse(newAcessToken, newRefreshTokenString);
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

    public async Task<ErrorOr<Success>> RevokeRefreshTokensAsync(string userId)
    {
        // Get the logged-in user's ID from JWT
        var currentUserId = GetCurrentUserId();
        if (currentUserId is null)
        {
            return Error.Forbidden("Auth.InvalidUser", "Could not determine the current user.");
        }

        // Ensure the user is only revoking their own refresh tokens
        if (userId != currentUserId)
        {
            return Error.Forbidden("RevokingRefreshToken", "You cannot revoke refresh tokens for another user.");
        }

        // Convert to GUID to match the RefreshToken.UserId property
        if (!Guid.TryParse(userId, out Guid parsedUserId))
        {
            return Error.Validation("User.InvalidId", "User ID is not a valid GUID.");
        }

        // Perform fast SQL DELETE
        await context.RefreshTokens
            .Where(r => r.UserId == userId)
            .ExecuteDeleteAsync();

        return Result.Success;
    }
}
