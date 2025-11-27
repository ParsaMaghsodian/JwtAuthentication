using FluentValidation;

namespace JwtAuthentication.DTO;

public record LoginUserWithRefreshTokenRequest(string RefreshToken);
public sealed class LoginUserWithRefreshTokenRequestValidator : AbstractValidator<LoginUserWithRefreshTokenRequest>
{
    public LoginUserWithRefreshTokenRequestValidator()
    {
        RuleFor(x => x.RefreshToken)
            .NotEmpty().WithMessage("Refresh token is required.")
            .MaximumLength(256).WithMessage("Maximum Refresh token is 256 characters");   
    }
}
