// Program.cs - .NET 8, OpenIddict 7.1.0 (Entra upstream with manual redemption; OpenIddict server for Okta)

using Idp_proxy.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.CookiePolicy;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using OpenIddict.Server.AspNetCore;
using Polly;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using static OpenIddict.Abstractions.OpenIddictConstants;

var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;

// Debug-friendly settings
Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

// Logging
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.AddFilter("Microsoft.IdentityModel", LogLevel.Debug);
builder.Logging.AddFilter("Microsoft.AspNetCore.Authentication", LogLevel.Debug);

// Data Protection (local key ring)
var keysDir = Path.Combine(builder.Environment.ContentRootPath, "keys");
Directory.CreateDirectory(keysDir);
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(keysDir))
    .SetApplicationName("IdpProxy");

builder.Services.AddControllersWithViews();

// Register factory for safe HttpClient usage (sockets pooled, no manual dispose)
builder.Services.AddHttpClient();

// ---------- Upstream OIDC: proxy is RP to Entra ----------
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "UpstreamOidc";
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, o =>
{
    o.Cookie.Name = ".idp_proxy.oidc";
    o.Cookie.SameSite = SameSiteMode.None;
    o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    o.SlidingExpiration = true;
})
.AddOpenIdConnect("UpstreamOidc", options =>
{
    var tenant = "6cd61cc7-553c-4adc-9d62-c36764ebc720";
    options.MetadataAddress = $"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration";

    // Keep a dedicated backchannel for the handler. Do NOT dispose this anywhere.
    options.Backchannel = new HttpClient(new SocketsHttpHandler
    {
        Proxy = WebRequest.DefaultWebProxy,
        UseProxy = true,
        AutomaticDecompression = DecompressionMethods.All,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5)
    })
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    options.ClientId = cfg["UpstreamOidc:ClientId"];
    options.ClientSecret = cfg["UpstreamOidc:ClientSecret"];

    options.ResponseType = OpenIdConnectResponseType.Code;
    options.ResponseMode = OpenIdConnectResponseMode.FormPost;
    options.UsePkce = true;

    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = false;

    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");

    options.CallbackPath = "/signin-oidc-upstream";

    options.CorrelationCookie.SameSite = SameSiteMode.None;
    options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
    options.NonceCookie.SameSite = SameSiteMode.None;
    options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;

    options.Events = new OpenIdConnectEvents
    {
        OnRedirectToIdentityProvider = async ctx =>
        {
            var absoluteCallback = $"{ctx.Request.Scheme}://{ctx.Request.Host}{ctx.Options.CallbackPath}";
            ctx.ProtocolMessage.RedirectUri = absoluteCallback;

               if (ctx.Properties?.Items != null &&
               ctx.Properties.Items.TryGetValue("login_hint", out var hint) &&
               !string.IsNullOrWhiteSpace(hint))
            {
                ctx.ProtocolMessage.SetParameter("login_hint", hint);
            }
            string authz = ctx.Options.Configuration?.AuthorizationEndpoint ?? "";
            if (string.IsNullOrEmpty(authz) && ctx.Options.ConfigurationManager is not null)
            {
                try
                {
                    var doc = await ctx.Options.ConfigurationManager.GetConfigurationAsync(ctx.HttpContext.RequestAborted);
                    authz = doc.AuthorizationEndpoint ?? "";
                    if (string.IsNullOrEmpty(authz) && !string.IsNullOrEmpty(doc.Issuer))
                    {
                        var baseIssuer = doc.Issuer.TrimEnd('/');
                        if (baseIssuer.EndsWith("/v2.0", StringComparison.OrdinalIgnoreCase))
                            baseIssuer = baseIssuer[..^"/v2.0".Length];
                        authz = $"{baseIssuer}/oauth2/v2.0/authorize";
                    }
                }
                catch
                {
                    // fall through
                }
            }

            if (string.IsNullOrEmpty(authz))
            {
                ctx.HandleResponse();
                ctx.Response.StatusCode = 500;
                await ctx.Response.WriteAsync("OIDC authorization endpoint could not be resolved.");
                return;
            }

            ctx.ProtocolMessage.IssuerAddress = authz;
        },

        // Manual code redemption (so we control the exact payload sent to /token)
        OnAuthorizationCodeReceived = async ctx =>
        {
            string? codeVerifier = null;
            if (ctx.TokenEndpointRequest != null &&
                ctx.TokenEndpointRequest.Parameters.TryGetValue("code_verifier", out var cv) &&
                !string.IsNullOrWhiteSpace(cv))
            {
                codeVerifier = cv;
            }

            var absoluteCallback = $"{ctx.Request.Scheme}://{ctx.Request.Host}{ctx.Options.CallbackPath}";

            var form = new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ctx.Options.ClientId!,
                ["client_secret"] = ctx.Options.ClientSecret!,
                ["code"] = ctx.ProtocolMessage.Code!,
                ["redirect_uri"] = absoluteCallback,
                ["scope"] = "openid profile email"
            };
            if (!string.IsNullOrWhiteSpace(codeVerifier))
                form["code_verifier"] = codeVerifier;

            using var req = new HttpRequestMessage(HttpMethod.Post,
                $"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token")
            { Content = new FormUrlEncodedContent(form) };

            // IMPORTANT: do NOT dispose the backchannel; if present, use it directly.
            // Otherwise, get a transient client from the factory (also not disposed here).
            var http = ctx.Options.Backchannel
                       ?? ctx.HttpContext.RequestServices
                           .GetRequiredService<IHttpClientFactory>()
                           .CreateClient();

            var resp = await http.SendAsync(req, ctx.HttpContext.RequestAborted);
            var payload = await resp.Content.ReadAsStringAsync(ctx.HttpContext.RequestAborted);

            if (!resp.IsSuccessStatusCode)
            {
                ctx.Fail($"Token request failed ({(int)resp.StatusCode}).");
                return;
            }

            using var json = System.Text.Json.JsonDocument.Parse(payload);
            var root = json.RootElement;

            var accessToken = root.TryGetProperty("access_token", out var at) ? at.GetString() : null;
            var idToken = root.TryGetProperty("id_token", out var idt) ? idt.GetString() : null;

            if (string.IsNullOrEmpty(accessToken) || string.IsNullOrEmpty(idToken))
            {
                ctx.Fail("Missing tokens in token response.");
                return;
            }

            ctx.HandleCodeRedemption(accessToken, idToken);
        }
    };
});

// ---------- OpenIddict: EF store + Server + Validation ----------
builder.Services.AddDbContext<AuthDbContext>(o =>
{
    o.UseInMemoryDatabase("idp-proxy");
    o.UseOpenIddict();
});

builder.Services.AddOpenIddict()
    .AddCore(o => o.UseEntityFrameworkCore().UseDbContext<AuthDbContext>())
    .AddServer(o =>
    {
        var origin = cfg["PublicOrigin"];
        if (!string.IsNullOrWhiteSpace(origin))
            o.SetIssuer(new Uri(origin));  // <-- IMPORTANT
        o.SetAuthorizationEndpointUris("/connect/authorize")
         .SetTokenEndpointUris("/connect/token")
         .SetIntrospectionEndpointUris("/connect/introspect");

        o.AllowImplicitFlow();

        o.AllowAuthorizationCodeFlow();
        o.RegisterScopes(Scopes.OpenId, Scopes.Profile, Scopes.Email);

        o.AddDevelopmentEncryptionCertificate()
         .AddDevelopmentSigningCertificate();

        o.UseAspNetCore()
         .EnableAuthorizationEndpointPassthrough();
        // .EnableTokenEndpointPassthrough();

        

        // --- Diagnostics (shows in Visual Studio Output -> Debug) ---
        o.AddEventHandler<OpenIddictServerEvents.HandleTokenRequestContext>(b =>
            b.UseInlineHandler(ctx =>
            {
                if (ctx.Request.IsAuthorizationCodeGrantType())
                {
                    var sub = ctx.Principal?.FindFirst(Claims.Subject)?.Value ?? "<missing>";
                    var presentersArray = Array.Empty<string>();
                    var presenters = ctx.Principal?.GetPresenters();
                    if (presenters is { IsDefaultOrEmpty: false } p)
                        presentersArray = p.ToArray();

                    Debug.WriteLine($"[TOKEN] code->principal sub={sub}, presenters=[{string.Join(",", presentersArray)}]");
                }
                return default;
            }));

        o.AddEventHandler<OpenIddictServerEvents.ApplyTokenResponseContext>(b =>
            b.UseInlineHandler(ctx =>
            {
                // Log the final error that will be sent to the client
                if (!string.IsNullOrEmpty(ctx.Response.Error))
                {
                    ctx.Transaction.Logger.LogError(
                        "TOKEN ERROR {Error}: {Description} (uri: {Uri})",
                        ctx.Response.Error,
                        ctx.Response.ErrorDescription,
                        ctx.Response.ErrorUri);
                }
                else
                {
                    ctx.Transaction.Logger.LogInformation(
                        "TOKEN OK for client_id={ClientId}, grant_type={GrantType}",
                        ctx.Request?.ClientId,
                        ctx.Request?.GrantType);
                }

                // Optional: dump grant type early
                System.Diagnostics.Debug.WriteLine(
                    $"[TOKEN] grant_type={ctx.Request?.GrantType ?? "<null>"}");

                // Optional: when issuing id_token, print claims
                var idt = ctx.Response.IdToken;
                if (!string.IsNullOrEmpty(idt))
                {
                    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                    var jwt = handler.ReadJwtToken(idt);
                    System.Diagnostics.Debug.WriteLine(
                        "[OIDC/TOKEN] id_token claims: " +
                        string.Join(", ", jwt.Claims.Select(c => $"{c.Type}={c.Value}")));
                }

                return default;
            }));




    })
    .AddValidation(o =>
    {
        o.UseLocalServer();
        o.UseAspNetCore();
    });

// Seed Okta client (descriptor below)
builder.Services.AddHostedService<OpenIddictSeed>();

builder.Services.Configure<ForwardedHeadersOptions>(o =>
{
    o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

var app = builder.Build();

app.UseForwardedHeaders();
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

app.UseCookiePolicy(new CookiePolicyOptions
{
    MinimumSameSitePolicy = SameSiteMode.None,
    HttpOnly = HttpOnlyPolicy.Always,
    Secure = CookieSecurePolicy.Always
});

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();

/// <summary>
/// Seeds the OpenIddict confidential client used by Okta to call your proxy
/// </summary>
public sealed class OpenIddictSeed : IHostedService
{
    private readonly IServiceProvider _sp;
    private readonly IConfiguration _cfg;

    public OpenIddictSeed(IServiceProvider sp, IConfiguration cfg)
    {
        _sp = sp;
        _cfg = cfg;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _sp.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        var clientId = _cfg["DownstreamOkta:ClientId"]!;
        var clientSecret = _cfg["DownstreamOkta:ClientSecret"]!;
        var oktaRedirect = _cfg["DownstreamOkta:RedirectUri"]!;

        var existing = await manager.FindByClientIdAsync(clientId, cancellationToken);
        if (existing is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                DisplayName = "Okta RP",
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Implicit,
                RedirectUris = { new Uri(oktaRedirect) },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.Introspection,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.Implicit,
                    Permissions.GrantTypes.ClientCredentials,
                    Permissions.ResponseTypes.Code,
                    Permissions.ResponseTypes.Token,
                    Permissions.ResponseTypes.IdToken,
                    Permissions.Prefixes.Scope + Scopes.OpenId,
                    Permissions.Prefixes.Scope + Scopes.Profile,
                    Permissions.Prefixes.Scope + Scopes.Email
                }
            }, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
