using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();


{
    var redisConnection = builder.Configuration["REDIS_CONNECTION"] ?? "localhost:6379";
    var redis = ConnectionMultiplexer.Connect(redisConnection);
    var redisDb = redis.GetDatabase();

    builder
        .Services.AddDataProtection()
        .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys")
        .SetApplicationName("MyApp");

    builder
        .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(
            CookieAuthenticationDefaults.AuthenticationScheme,
            options =>
            {
                options.Events.OnSignedIn = async context =>
                {
                    var sessionId = Guid.NewGuid().ToString();
                    var userId = context.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

                    if (!string.IsNullOrEmpty(userId))
                    {
                        await redisDb.StringSetAsync(
                            $"session:{sessionId}",
                            userId,
                            TimeSpan.FromHours(1)
                        );

                        var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;
                        claimsIdentity.AddClaim(new Claim("SessionId", sessionId));
                    }
                };

                options.Events.OnValidatePrincipal = async context =>
                {
                    var sessionId = context.Principal.FindFirst("SessionId")?.Value;
                    if (string.IsNullOrEmpty(sessionId))
                    {
                        context.RejectPrincipal(); // Force re-login
                        return;
                    }

                    // Check if session exists in Redis
                    var userId = await redisDb.StringGetAsync($"session:{sessionId}");
                    if (userId.IsNullOrEmpty)
                    {
                        context.RejectPrincipal(); // Session expired, force logout
                    }
                };

                //options.LoginPath = "/Account/Login";
                //options.AccessDeniedPath = "/Account/AccessDenied";
                //options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            }
        );
}

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

// app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
