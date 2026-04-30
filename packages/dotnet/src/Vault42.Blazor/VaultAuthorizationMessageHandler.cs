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
