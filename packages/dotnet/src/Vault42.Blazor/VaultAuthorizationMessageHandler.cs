using System.Net.Http.Headers;

namespace Vault42.Blazor;

/// <summary>
/// DelegatingHandler that automatically attaches the Vault Bearer access token
/// to outgoing HTTP requests. Register with HttpClient via AddHttpMessageHandler.
/// </summary>
public sealed class VaultAuthorizationMessageHandler : DelegatingHandler
{
    private readonly VaultAuthService _authService;

    internal VaultAuthorizationMessageHandler(VaultAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Attaches the current access token and, for safe methods, retries once after refreshing on a 401.
    /// </summary>
    /// <param name="request">The outgoing request. Any existing <c>Authorization</c> header is replaced when a token is held.</param>
    /// <param name="cancellationToken">Cancels the send and any retry.</param>
    /// <returns>The server's response, or the response to the retried request when a refresh succeeded.</returns>
    /// <remarks>
    /// The retry is limited to <c>GET</c>, <c>HEAD</c> and <c>OPTIONS</c>. An unsafe method may
    /// already have taken effect server-side before the 401 was written, so replaying it could
    /// duplicate a state change; those methods surface the 401 to the caller instead. There is at
    /// most one retry, and only when a token was already held, so an anonymous request that gets a
    /// 401 is returned as-is.
    /// </remarks>
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = _authService.AccessToken;
        if (!string.IsNullOrEmpty(token))
        {
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }

        var response = await base.SendAsync(request, cancellationToken);

        // CS-13: Only auto-retry safe (idempotent) methods on 401. POST/PATCH/DELETE
        // could have already taken effect server-side — silently retrying risks
        // duplicate state changes. Surface the 401 to the caller for unsafe methods
        // and let them decide.
        if (response.StatusCode == System.Net.HttpStatusCode.Unauthorized
            && !string.IsNullOrEmpty(token)
            && IsSafeForAutoRetry(request.Method))
        {
            if (await _authService.RefreshAsync())
            {
                var newToken = _authService.AccessToken;
                if (!string.IsNullOrEmpty(newToken))
                {
                    var retryRequest = await CloneRequestAsync(request);
                    retryRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", newToken);
                    response.Dispose();
                    response = await base.SendAsync(retryRequest, cancellationToken);
                }
            }
        }

        return response;
    }

    private static bool IsSafeForAutoRetry(HttpMethod m) =>
        m == HttpMethod.Get || m == HttpMethod.Head || m == HttpMethod.Options;

    private static async Task<HttpRequestMessage> CloneRequestAsync(HttpRequestMessage request)
    {
        var clone = new HttpRequestMessage(request.Method, request.RequestUri);
        foreach (var header in request.Headers)
            clone.Headers.TryAddWithoutValidation(header.Key, header.Value);

        if (request.Content is not null)
        {
            var content = await request.Content.ReadAsByteArrayAsync();
            clone.Content = new ByteArrayContent(content);
            if (request.Content.Headers.ContentType is not null)
                clone.Content.Headers.ContentType = request.Content.Headers.ContentType;
        }

        return clone;
    }
}
