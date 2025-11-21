namespace JwtAuthentication.Shared;

public class JwtConfiguration
{
    public string Issuer { get; init; }
    public string Audience { get; init; }
    public int ExpirationInMinutes { get; init; }
    public string SecretKey { get; init; }
}
