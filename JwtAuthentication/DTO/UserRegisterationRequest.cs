using FluentValidation;

namespace JwtAuthentication.DTO;

public record UserRegisterationRequest(string FirstName, string LastName, string UserName, string Password, string PhoneNumber);

public sealed class UserRegisterationRequestValidator : AbstractValidator<UserRegisterationRequest>
{
    public UserRegisterationRequestValidator()
    {
        RuleFor(x => x.FirstName)
            .NotEmpty().WithMessage("First name is required.");
        RuleFor(x => x.LastName)
            .NotEmpty().WithMessage("Last name is required.");
        RuleFor(x => x.UserName)
            .NotEmpty().WithMessage("Username is required.");
        RuleFor(x => x.Password)
            .NotEmpty().WithMessage("Password is required.")
    .MinimumLength(8).WithMessage("Password must be at least 8 characters long.")
    .Matches("[A-Z]").WithMessage("Password must contain at least one uppercase letter.")
    .Matches("[a-z]").WithMessage("Password must contain at least one lowercase letter.")
    .Matches("[0-9]").WithMessage("Password must contain at least one number.")
    .Matches("[^a-zA-Z0-9]").WithMessage("Password must contain at least one special character.");
        RuleFor(x => x.PhoneNumber)
            .NotEmpty().WithMessage("Phone number is required.")
                                   .Matches(@"^\+?[1-9]\d{1,14}$").WithMessage("Invalid phone number format.");
    }
}
