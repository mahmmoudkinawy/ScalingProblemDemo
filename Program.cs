using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using StackExchange.Redis;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();


{
    var redisConnection = builder.Configuration["REDIS_CONNECTION"] ?? "localhost:6379";
    var redis = ConnectionMultiplexer.Connect(redisConnection);

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
                options.LoginPath = "/Account/Login";
                options.AccessDeniedPath = "/Account/AccessDenied";
                options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
            }
        );
}

var app = builder.Build();

app.Use(
    async (context, next) =>
    {
        var cookie = context.Request.Cookies[".AspNetCore.Cookies"];
        if (!string.IsNullOrEmpty(cookie))
        {
            var dataProtector = context
                .RequestServices.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(
                    "Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationMiddleware"
                );

            try
            {
                var decryptedValue = dataProtector.Unprotect(cookie);
                Console.WriteLine("Decrypted Cookie: " + decryptedValue);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Failed to decrypt: " + ex.Message);
            }
        }
        await next();
    }
);

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
