using ErrorOr;
using JwtAuthentication.DTO;

namespace JwtAuthentication.Services;

public interface IUserService
{
    Task<string> RegisterUserAsync(UserRegisterationRequest request);
    Task<ErrorOr<string>> LoginUserAsync(LoginUserRequest request);
}