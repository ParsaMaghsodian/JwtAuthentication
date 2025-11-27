using ErrorOr;
using JwtAuthentication.DTO;

namespace JwtAuthentication.Services;

public interface IUserService
{
    Task<string> RegisterUserAsync(UserRegisterationRequest request);
    Task<ErrorOr<LoginUserResponse>> LoginUserAsync(LoginUserRequest request);
    Task<ErrorOr<LoginUserWithRefreshTokenResponse>> LoginUserWithRefreshTokenAsync(LoginUserWithRefreshTokenRequest request);
    Task<ErrorOr<Success>> RevokeRefreshTokensAsync(string userId);
}