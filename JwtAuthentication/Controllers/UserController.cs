using JwtAuthentication.DTO;
using JwtAuthentication.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JwtAuthentication.Controllers;

[Route("api/[controller]")]
[ApiController]
public class UserController(IUserService userService) : ControllerBase
{
    [HttpPost("register")]
    public async Task<IActionResult> RegisterUser(UserRegisterationRequest request)
    {
        string result = await userService.RegisterUserAsync(request);

        return string.IsNullOrEmpty(result)
           ? Ok("User registered successfully.")
           : BadRequest(result);
    }
    [HttpPost("login")]
    public async Task<IActionResult> LoginUser(LoginUserRequest request)
    {
        var result = await userService.LoginUserAsync(request);

        return result.Match<IActionResult>(
                 // SUCCESS CASE
                 response => Ok(new
                 {
                     accessToken = response.AcessToken,
                     refreshToken = response.RefreshToken
                 }),

                 // ERROR CASE
                 errors => BadRequest(errors)
             );
    }
    [HttpPost("login/refresh-token")]
    public async Task<IActionResult> LoginUserWithRefreshToken(LoginUserWithRefreshTokenRequest request)
    {
        var result = await userService.LoginUserWithRefreshTokenAsync(request);
        return result.Match<IActionResult>(
                 // SUCCESS CASE
                 response => Ok(new
                 {
                     accessToken = response.AccessToken,
                     refreshToken = response.RefreshToken
                 }),
                 // ERROR CASE
                 errors => BadRequest(errors)
             );
    }
    [Authorize]
    [HttpDelete("refresh-tokens/{userId}")]
    public async Task<IActionResult> RevokeUserRefreshTokens(string userId)
    {
        var result = await userService.RevokeRefreshTokensAsync(userId);

        return result.Match<IActionResult>(
            // SUCCESS
            _ => Ok(new { message = "Refresh tokens revoked successfully." }),

            // ERROR
            errors => BadRequest(errors)
        );
    }

}
