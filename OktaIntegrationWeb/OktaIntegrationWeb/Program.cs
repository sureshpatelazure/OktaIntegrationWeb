using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "Okta";
}).AddCookie()
.AddOAuth("Okta", options => {

    // Oauth authentication middleware is second

     var oktaDomain = builder.Configuration["Okta:Domain"];

    // When a user needs to sign in, they will be redirected to the authorize endpoint
    options.AuthorizationEndpoint = $"{oktaDomain}/oauth2/default/v1/authorize";

    // Okta's OAuth server is OpenID compliant, so request the standard openid
    // scopes when redirecting to the authorization endpoint
    options.Scope.Add("openid");
    options.Scope.Add("profile");
    options.Scope.Add("email");

    // After the user signs in, an authorization code will be sent to a callback
    // in this app. The OAuth middleware will intercept it
    options.CallbackPath = new PathString("/authorization-code/callback");

    // The OAuth middleware will send the ClientId, ClientSecret, and the
    // authorization code to the token endpoint, and get an access token in return
    options.ClientId = builder.Configuration["Okta:ClientId"].ToString();  
    options.ClientSecret = builder.Configuration["Okta:ClientSecret"].ToString(); 
    options.TokenEndpoint = $"{oktaDomain}/oauth2/default/v1/token";

    // Below we call the userinfo endpoint to get information about the user
    options.UserInformationEndpoint = $"{oktaDomain}/oauth2/default/v1/userinfo";

    // Describe how to map the user info we receive to user claims
    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "given_name");   
    options.ClaimActions.MapJsonKey(ClaimTypes.Email, "email"); 

    options.Events = new OAuthEvents
    {
        OnCreatingTicket = async context =>
        {
            // Get user info from the userinfo endpoint and use it to populate user claims
            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);  
            request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));    
            request.Headers.Add("Authorization", $"Bearer {context.AccessToken}");  

            var response = await context.Backchannel.SendAsync(request, context.HttpContext.RequestAborted);
            response.EnsureSuccessStatusCode();

            var userJson = await response.Content.ReadAsStringAsync();
            using var doc = System.Text.Json.JsonDocument.Parse(userJson);
            context.RunClaimActions(doc.RootElement);
            ;
        }
    };

});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
