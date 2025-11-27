namespace JwtAuthentication.DTO;

public record LoginUserWithRefreshTokenResponse(string AccessToken, string RefreshToken);