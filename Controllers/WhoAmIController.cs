using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens; // Base64UrlEncoder

namespace Idp_proxy.Controllers
{
    [Route("whoami")]
    [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
    public class WhoAmIController : Controller
    {
        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var auth = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!auth.Succeeded || auth.Principal == null)
            {
                var challengeProps = new AuthenticationProperties { RedirectUri = Url.Action(nameof(Get)) };
                return Challenge(challengeProps, "UpstreamOidc");
            }

            var user = auth.Principal;

            // Common email/name fallbacks from Entra ID
            var email = user.FindFirst(ClaimTypes.Email)?.Value
                     ?? user.FindFirst("email")?.Value
                     ?? user.FindFirst("preferred_username")?.Value
                     ?? user.Identity?.Name
                     ?? string.Empty;

            // Prefer tokens stored on the auth ticket (SaveTokens = true)
            var ticketProps = auth.Properties;
            var accessToken = ticketProps.GetTokenValue("access_token");
            var idToken = ticketProps.GetTokenValue("id_token");
            var expiresAt = ticketProps.GetTokenValue("expires_at");

            var handler = new JwtSecurityTokenHandler();

            string idAud = string.Empty, idIss = string.Empty, idSub = string.Empty, idTid = string.Empty;
            Dictionary<string, string[]>? idClaims = null;

            if (!string.IsNullOrEmpty(idToken))
            {
                try
                {
                    var jwt = handler.ReadJwtToken(idToken);
                    idAud = jwt.Audiences.FirstOrDefault() ?? string.Empty;
                    idIss = jwt.Issuer ?? string.Empty;
                    idSub = jwt.Claims.FirstOrDefault(c => c.Type == "sub")?.Value ?? string.Empty;
                    idTid = jwt.Claims.FirstOrDefault(c => c.Type == "tid")?.Value ?? string.Empty;
                    idClaims = jwt.Claims
                        .GroupBy(c => c.Type)
                        .ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray());
                }
                catch
                {
                    // ignore parse errors
                }
            }

            // Determine device posture
            bool managed = false, compliant = false;

            // 1) Prefer deriving from upstream access token (signin_state)
            if (!string.IsNullOrEmpty(accessToken))
            {
                try
                {
                    var atJwt = handler.ReadJwtToken(accessToken);
                    var rawJson = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.Decode(atJwt.RawPayload);
                    using var doc = System.Text.Json.JsonDocument.Parse(rawJson);

                    if (doc.RootElement.TryGetProperty("signin_state", out var node))
                    {
                        var states = new List<string>();

                        if (node.ValueKind == JsonValueKind.Array)
                        {
                            states.AddRange(node.EnumerateArray()
                                .Where(e => e.ValueKind == JsonValueKind.String)
                                .Select(e => e.GetString()!));
                        }
                        else if (node.ValueKind == JsonValueKind.String)
                        {
                            states.Add(node.GetString()!);
                        }

                        managed = states.Contains("dvc_mngd", StringComparer.OrdinalIgnoreCase);
                        compliant = states.Contains("dvc_cmp", StringComparer.OrdinalIgnoreCase);
                    }


                }
                catch { }
            }


            // 2) If still unknown, fallback to your server-issued device_context claim (JSON: { managed, compliant })
            if (!managed && !compliant)
            {
                var dcRaw = user.FindFirst("device_context")?.Value;
                if (!string.IsNullOrWhiteSpace(dcRaw))
                {
                    try
                    {
                        var dc = JsonSerializer.Deserialize<DeviceContext>(dcRaw);
                        if (dc != null)
                        {
                            managed = managed || dc.managed;
                            compliant = compliant || dc.compliant;
                        }
                    }
                    catch
                    {
                        // ignore malformed JSON
                    }
                }
            }

            var payload = new
            {
                sub = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? email,
                email,
                device_context = new { managed, compliant }, // no externalId here
                all_cookie_claims = user.Claims
                    .GroupBy(c => c.Type)
                    .ToDictionary(g => g.Key, g => g.Select(c => c.Value).ToArray()),
                tokens = new
                {
                    access_token_present = !string.IsNullOrEmpty(accessToken),
                    id_token_present = !string.IsNullOrEmpty(idToken),
                    expires_at = expiresAt,
                    id_token_debug = new
                    {
                        aud = idAud,
                        iss = idIss,
                        sub = idSub,
                        tid = idTid,
                        claims = idClaims
                    }
                }
            };

            return Ok(payload);
        }
        private readonly ILogger<WhoAmIController> _logger;

        public WhoAmIController(ILogger<WhoAmIController> logger)
        {
            _logger = logger;
        }

        private static List<string> GetSigninStateFromClaims(JwtSecurityToken jwt)
        {
            // Multiple claims with same type
            var values = jwt.Claims.Where(c => c.Type == "signin_state").Select(c => c.Value).ToList();

            // Some tenants pack into one delimited string
            if (values.Count == 0)
            {
                var s = jwt.Claims.FirstOrDefault(c => c.Type == "signin_state")?.Value;
                if (!string.IsNullOrWhiteSpace(s))
                {
                    values = SplitDelimited(s);
                }
            }

            return values;
        }

        private static List<string> GetSigninStateValues(JwtSecurityToken jwt)
        {
            if (jwt.Payload.TryGetValue("signin_state", out var raw) && raw is not null)
            {
                if (raw is System.Text.Json.JsonElement je)
                {
                    if (je.ValueKind == System.Text.Json.JsonValueKind.Array)
                    {
                        var list = new List<string>();
                        foreach (var item in je.EnumerateArray())
                        {
                            if (item.ValueKind == System.Text.Json.JsonValueKind.String)
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
                    if (je.ValueKind == System.Text.Json.JsonValueKind.String)
                    {
                        var s = je.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                        {
                            if (s.TrimStart().StartsWith("[")) // JSON array as string
                            {
                                try
                                {
                                    var arr = System.Text.Json.JsonSerializer.Deserialize<string[]>(s);
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
                            var arr = System.Text.Json.JsonSerializer.Deserialize<string[]>(s2);
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

        private static List<string> SplitDelimited(string s) =>
            s.Split(new[] { ' ', ',', ';' }, StringSplitOptions.RemoveEmptyEntries)
             .Select(x => x.Trim())
             .Where(x => x.Length > 0)
             .ToList();



        private sealed class DeviceContext
        {
            public bool managed { get; set; }
            public bool compliant { get; set; }
        }
    }
}
