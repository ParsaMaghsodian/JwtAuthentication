using JwtAuthentication.DTO;
using JwtAuthentication.Services;
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
              accessToken => Ok(new { accessToken }),
              errors => BadRequest(errors)
          );
    }
}
