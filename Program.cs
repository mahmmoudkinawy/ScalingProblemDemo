using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();


{
    var redisConnection = builder.Configuration["REDIS_CONNECTION"] ?? "localhost:6379";
    var redis = ConnectionMultiplexer.Connect(redisConnection);

    // Register in DI
    builder.Services.AddSingleton<IConnectionMultiplexer>(redis);

    builder
        .Services.AddDataProtection()
        .PersistKeysToStackExchangeRedis(redis, "DataProtection-Keys")
        .SetApplicationName("MyApp") // MUST BE THE SAME ACROSS INSTANCES
        .SetDefaultKeyLifetime(TimeSpan.FromDays(90)); // Prevents premature key expiration

    builder
        .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.LoginPath = "/account/login";
            options.AccessDeniedPath = "/account/accessdenied";
        });

    //builder
    //    .Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    //    .AddCookie(
    //        CookieAuthenticationDefaults.AuthenticationScheme,
    //        options =>
    //        {
    //            options.Events.OnSignedIn = async context =>
    //            {
    //                var sessionId = Guid.NewGuid().ToString();
    //                var userId = context.Principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;

    //                if (!string.IsNullOrEmpty(userId))
    //                {
    //                    await redisDb.StringSetAsync(
    //                        $"session:{sessionId}",
    //                        userId,
    //                        TimeSpan.FromHours(1)
    //                    );

    //                    var claimsIdentity = (ClaimsIdentity)context.Principal.Identity;
    //                    claimsIdentity.AddClaim(new Claim("SessionId", sessionId));
    //                }
    //            };

    //            options.Events.OnValidatePrincipal = async context =>
    //            {
    //                var sessionId = context.Principal.FindFirst("SessionId")?.Value;
    //                if (string.IsNullOrEmpty(sessionId))
    //                {
    //                    context.RejectPrincipal(); // Force re-login
    //                    return;
    //                }

    //                // Check if session exists in Redis
    //                var userId = await redisDb.StringGetAsync($"session:{sessionId}");
    //                if (userId.IsNullOrEmpty)
    //                {
    //                    context.RejectPrincipal(); // Session expired, force logout
    //                }
    //            };

    //            //options.LoginPath = "/Account/Login";
    //            //options.AccessDeniedPath = "/Account/AccessDenied";
    //            //options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    //        }
    //    );
}

var app = builder.Build();

var keyManager = app.Services.GetRequiredService<IKeyManager>();
foreach (var key in keyManager.GetAllKeys())
{
    Console.WriteLine($"KeyId: {key.KeyId}, Created: {key.CreationDate}");
}

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
