using System.Text.Json.Serialization;

namespace Vault42.Blazor.Internal;

/// <summary>
/// The body both <c>POST /auth/oauth2/exchange</c> and <c>POST /auth/refresh</c> answer with.
/// </summary>
/// <remarks>
/// A Vault server never populates <see cref="RefreshToken"/>: both its handlers declare that field
/// <c>json:"-"</c> and set the refresh token as a <c>__Host-refresh_token</c> cookie instead. It is
/// read here so the SDK can also front an issuer that returns one in the body, which is the only
/// way <see cref="RefreshTokenStorage.InMemoryOnly"/> and
/// <see cref="RefreshTokenStorage.SessionStorage"/> ever receive anything to store.
/// </remarks>
internal sealed class TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }
}

/// <summary>
/// The entire request body <c>POST /auth/oauth2/exchange</c> accepts.
/// </summary>
/// <remarks>
/// The server decodes it with unknown fields disallowed, so this type must carry exactly one
/// property. Adding a <c>grant_type</c>, <c>client_id</c>, <c>redirect_uri</c> or
/// <c>code_verifier</c> alongside the code -- the shape a normal OAuth2 token request has -- turns
/// every exchange into a 400 <c>invalid_request</c>.
/// </remarks>
internal sealed class ExchangeRequest
{
    [JsonPropertyName("code")]
    public string Code { get; set; } = string.Empty;
}
