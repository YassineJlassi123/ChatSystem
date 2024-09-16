using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.SignalR;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.PropertyNamingPolicy = null; // Use this to keep property names as-is
});
builder.Services.AddRazorPages();  // Add Razor Pages support

// Get sensitive values from environment variables
var connectionString = Environment.GetEnvironmentVariable("DefaultConnection") ?? throw new InvalidOperationException("Connection string not configured.");
var jwtIssuer = Environment.GetEnvironmentVariable("JwtIssuer") ?? throw new InvalidOperationException("JWT Issuer not configured.");
var jwtAudience = Environment.GetEnvironmentVariable("JwtAudience") ?? throw new InvalidOperationException("JWT Audience not configured.");
var jwtKey = Environment.GetEnvironmentVariable("JwtKey") ?? throw new InvalidOperationException("JWT Key not configured.");
var googleClientId = Environment.GetEnvironmentVariable("GoogleClientId") ?? throw new InvalidOperationException("Google Client ID not configured.");
var googleClientSecret = Environment.GetEnvironmentVariable("GoogleClientSecret") ?? throw new InvalidOperationException("Google Client Secret not configured.");

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString));

// Register TokenService
builder.Services.AddScoped<TokenService>();
builder.Services.AddSignalR().AddJsonProtocol(options =>
{
    options.PayloadSerializerOptions.PropertyNamingPolicy = null;
});
builder.Services.AddSingleton<IUserIdProvider, CustomUserIdProvider>();

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme; // Use Cookie for default challenge
})
.AddCookie(options =>
{
    options.LoginPath = "/Account/Login"; // Redirect to Login if unauthorized
})
.AddJwtBearer(options =>
{
    options.Events = new JwtBearerEvents
    {
        OnMessageReceived = context =>
        {
            // Extract JWT token from cookie
            var token = context.Request.Cookies["jwtToken"];
            if (!string.IsNullOrEmpty(token))
            {
                context.Token = token;
            }
            return Task.CompletedTask;
        }
    };
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtKey))
    };
})
.AddGoogle(options =>
{
    options.ClientId = googleClientId;
    options.ClientSecret = googleClientSecret;
    options.CallbackPath = "/signin-google"; // This should match the URI registered in Google API Console
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication(); // Authentication must be configured before authorization
app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapControllerRoute(
        name: "default",
        pattern: "{controller=Account}/{action=Login}/{id?}"); // Default route to Login action
    endpoints.MapHub<FriendHub>("/FriendHub");  // Add this line
    endpoints.MapRazorPages();
});

app.Run();
