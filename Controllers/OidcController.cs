using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens; // Base64UrlEncoder
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Json;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Idp_proxy.Controllers
{
    [Route("")]
    public class OidcController : Controller
    {
        private readonly IConfiguration _cfg;
        private readonly IHttpClientFactory _http;
        private readonly ILogger<OidcController> _logger;

        public OidcController(IConfiguration cfg, IHttpClientFactory http, ILogger<OidcController> logger)
        {
            _cfg = cfg;
            _http = http;
            _logger = logger;
        }

        // /connect/authorize (Okta calls this)
        [HttpGet("~/connect/authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                         ?? throw new InvalidOperationException("Cannot read OIDC request.");

            var auth = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!auth.Succeeded || auth.Principal is null)
            {
                var returnUrl = "/connect/authorize" + QueryString.Create(
                    Request.Query.Select(kvp => new KeyValuePair<string, string?>(kvp.Key, kvp.Value.ToString()))
                );

                var props = new AuthenticationProperties
                {
                    RedirectUri = Url.Action(nameof(AuthorizeCallback), new { returnUrl })
                };

                // carry the Okta login_hint forward to Entra
                var loginHint = request.LoginHint ?? Request.Query["login_hint"].ToString();
                if (!string.IsNullOrWhiteSpace(loginHint))
                    props.Items["login_hint"] = loginHint;

                return Challenge(props, "UpstreamOidc");
            }

            // Build the principal we’ll issue to Okta
            var principal = BuildBrokerPrincipal(auth);

            // Mirror requested scopes and set a resource if you use one
            principal.SetScopes(request.GetScopes());
            // principal.SetResources("idp-proxy");

            // Bind the code to Okta client_id (prevents cross-client redemption)
            if (!string.IsNullOrEmpty(request.ClientId))
                principal.SetPresenters(request.ClientId);

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Upstream OIDC returns here after login
        [HttpGet("authorize-callback")]
        public IActionResult AuthorizeCallback([FromQuery] string? returnUrl)
        {
            if (string.IsNullOrEmpty(returnUrl)) returnUrl = "/connect/authorize";
            return LocalRedirect(returnUrl);
        }

        // /connect/token handled by OpenIddict (passthrough)
        [HttpPost("~/connect/token")]
        public IActionResult Token() => Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        /// <summary>
        /// Build the principal that OpenIddict will serialize into id_token/access_token for Okta.
        /// Identity claims are pulled from the upstream id_token; device posture comes from the access token (signin_state).
        /// </summary>
        private ClaimsPrincipal BuildBrokerPrincipal(AuthenticateResult upstreamAuth)
        {
            var upstream = upstreamAuth.Principal!;
            var props = upstreamAuth.Properties ?? new AuthenticationProperties();

            // --- 1) Read identity from Entra id_token (raw payload) ---
            var idToken = props.GetTokenValue("id_token");
            string? preferredUsername = null;
            string? email = null;
            string? entradaSub = null;

            if (!string.IsNullOrEmpty(idToken))
            {
                var idJwt = new JwtSecurityTokenHandler().ReadJwtToken(idToken);

                // Use RAW payload so we don't lose claims due to inbound mapping/filtering
                preferredUsername = GetStringFromRawPayload(idJwt, "preferred_username");
                entradaSub = GetStringFromRawPayload(idJwt, "sub");
                email = GetStringFromRawPayload(idJwt, "email");
            }

            // Sensible fallbacks if Entra didn’t include fields (or in older tenants)
            preferredUsername ??= upstream.FindFirst("preferred_username")?.Value
                               ?? upstream.FindFirst(ClaimTypes.Upn)?.Value
                               ?? upstream.Identity?.Name
                               ?? "unknown@example.com";

            email ??= upstream.FindFirst("email")?.Value ?? preferredUsername;

            // --- 2) Derive device posture from the Entra access_token only ---
            bool managed = false, compliant = false;
            var accessToken = props.GetTokenValue("access_token");
            if (!string.IsNullOrEmpty(accessToken))
            {
                try
                {
                    var atJwt = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

                    // Use the same robust parsing you have in WhoAmI
                    var states = GetSigninStateValues(atJwt);
                    if (states.Count == 0)
                    {
                        // Fallback to raw JSON payload parsing (also in WhoAmI style)
                        states = GetSigninStateFromRawPayload(atJwt);
                    }

                    managed = states.Contains("dvc_mngd", StringComparer.OrdinalIgnoreCase);
                    compliant = states.Contains("dvc_cmp", StringComparer.OrdinalIgnoreCase);

                    _logger.LogInformation("Derived device posture from access_token: managed={Managed}, compliant={Compliant}", managed, compliant);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to parse signin_state from upstream access token.");
                }
            }

            // --- 3) Build the broker principal for OpenIddict (what Okta will receive) ---
            var id = new ClaimsIdentity(authenticationType: "idp-proxy",
                                        nameType: Claims.Name,
                                        roleType: Claims.Role);

            // IMPORTANT: Set 'sub' for Okta. Use preferred_username (UPN) as your stable external identifier.
            id.AddClaim(new Claim(OpenIddictConstants.Claims.Subject, preferredUsername)
                .SetDestinations(OpenIddictConstants.Destinations.IdentityToken));

            // Include preferred_username explicitly too (handy for clients)
            id.AddClaim(new Claim("preferred_username", preferredUsername)
                .SetDestinations(OpenIddictConstants.Destinations.IdentityToken,
                                 OpenIddictConstants.Destinations.AccessToken));

            if (!string.IsNullOrEmpty(email))
            {
                id.AddClaim(new Claim(OpenIddictConstants.Claims.Email, email)
                    .SetDestinations(OpenIddictConstants.Destinations.IdentityToken,
                                     OpenIddictConstants.Destinations.AccessToken));
            }

            // Optionally expose the original Entra subject for traceability (not required by Okta)
            if (!string.IsNullOrEmpty(entradaSub))
            {
                id.AddClaim(new Claim("entra_sub", entradaSub)
                    .SetDestinations(OpenIddictConstants.Destinations.AccessToken));
            }

            var deviceContext = new { managed, compliant, externalId = "123" };
            var dcClaim = new Claim(
                    "device_context",
                    JsonSerializer.Serialize(deviceContext),
                    JsonClaimValueTypes.Json // <-- this makes it a JSON object claim
             )
            .SetDestinations(OpenIddictConstants.Destinations.IdentityToken,
                 OpenIddictConstants.Destinations.AccessToken);

            id.AddClaim(dcClaim);

            var principal = new ClaimsPrincipal(id);

            //Log claims returned back to Okta RP for debugging
            try
            {
                var claimsDump = principal.Claims
                    .GroupBy(c => c.Type)
                    .ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray());
                var json = JsonSerializer.Serialize(claimsDump, new JsonSerializerOptions { WriteIndented = true });
                _logger.LogWarning("Broker principal to be issued:\n{ClaimsJson}", json);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to log broker principal claims");

            }
            return principal;
            //return new ClaimsPrincipal(id);
    
        }

        // ---------- Helpers copied/adapted from WhoAmI (robust signin_state parsing) ----------

        // Prefer payload-based parsing; handles array, string, or JSON-as-string
        private static List<string> GetSigninStateValues(JwtSecurityToken jwt)
        {
            if (jwt.Payload.TryGetValue("signin_state", out var raw) && raw is not null)
            {
                if (raw is JsonElement je)
                {
                    if (je.ValueKind == JsonValueKind.Array)
                    {
                        var list = new List<string>();
                        foreach (var item in je.EnumerateArray())
                        {
                            if (item.ValueKind == JsonValueKind.String)
                            {
                                var s = item.GetString();
                                if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                            }
                            else
                            {
                                var s = item.ToString();
                                if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                            }
                        }
                        return list;
                    }
                    if (je.ValueKind == JsonValueKind.String)
                    {
                        var s = je.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                        {
                            // Sometimes providers serialize an array as a string containing JSON
                            if (s.TrimStart().StartsWith("["))
                            {
                                try
                                {
                                    var arr = JsonSerializer.Deserialize<string[]>(s);
                                    if (arr != null) return arr.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                                }
                                catch { }
                            }
                            return SplitDelimited(s);
                        }
                    }
                    var t = je.ToString();
                    if (!string.IsNullOrWhiteSpace(t)) return SplitDelimited(t);
                    return new List<string>();
                }

                if (raw is IEnumerable<object> seq && raw is not string)
                {
                    var list = new List<string>();
                    foreach (var item in seq)
                    {
                        var s = item?.ToString();
                        if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                    }
                    return list;
                }

                if (raw is string s2 && !string.IsNullOrWhiteSpace(s2))
                {
                    if (s2.TrimStart().StartsWith("["))
                    {
                        try
                        {
                            var arr = JsonSerializer.Deserialize<string[]>(s2);
                            if (arr != null) return arr.Where(x => !string.IsNullOrWhiteSpace(x)).ToList();
                        }
                        catch { }
                    }
                    return SplitDelimited(s2);
                }

                var t2 = raw.ToString();
                if (!string.IsNullOrWhiteSpace(t2)) return SplitDelimited(t2);
            }
            return new List<string>();
        }

        // Fallback: raw JSON payload decode
        private static List<string> GetSigninStateFromRawPayload(JwtSecurityToken jwt)
        {
            try
            {
                var raw = Base64UrlEncoder.Decode(jwt.RawPayload);
                using var doc = JsonDocument.Parse(raw);
                if (!doc.RootElement.TryGetProperty("signin_state", out var node))
                    return new List<string>();

                var list = new List<string>();

                if (node.ValueKind == JsonValueKind.Array)
                {
                    foreach (var item in node.EnumerateArray())
                    {
                        if (item.ValueKind == JsonValueKind.String)
                        {
                            var s = item.GetString();
                            if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                        }
                        else
                        {
                            var s = item.ToString();
                            if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
                        }
                    }
                    return list;
                }

                if (node.ValueKind == JsonValueKind.String)
                {
                    var s = node.GetString();
                    return SplitDelimited(s ?? string.Empty);
                }

                var t = node.ToString();
                return SplitDelimited(t);
            }
            catch
            {
                return new List<string>();
            }
        }

        // Helper: read a single string claim from the RAW JWT payload JSON (no filtering)
        private static string? GetStringFromRawPayload(JwtSecurityToken jwt, string name)
        {
            try
            {
                var raw = Base64UrlEncoder.Decode(jwt.RawPayload);
                using var doc = JsonDocument.Parse(raw);
                if (!doc.RootElement.TryGetProperty(name, out var node))
                    return null;
                return node.ValueKind == JsonValueKind.String ? node.GetString() : node.ToString();
            }
            catch
            {
                return null;
            }
        }

        private static List<string> SplitDelimited(string s) =>
            s.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
             .Select(x => x.Trim())
             .Where(x => x.Length > 0)
             .ToList();
    }
}
