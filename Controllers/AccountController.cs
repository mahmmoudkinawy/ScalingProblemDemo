using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using StackExchange.Redis;

namespace ScalingProblemDemo.Controllers;

public class AccountController(IConfiguration configuration) : Controller
{
    [HttpGet]
    public IActionResult Login() => View();

    [HttpPost]
    public async Task<IActionResult> Login(string username, string password)
    {
        if (username == "admin" && password == "123") // Replace with real validation
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, username) };
            var identity = new ClaimsIdentity(
                claims,
                CookieAuthenticationDefaults.AuthenticationScheme
            );
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal
            );
            return RedirectToAction("Index", "Home");
        }

        ViewBag.Message = "Invalid login";
        return View();
    }

    public async Task<IActionResult> Logout()
    {
        var sessionId = User.FindFirst("SessionId")?.Value;
        if (!string.IsNullOrEmpty(sessionId))
        {
            var redisDb = ConnectionMultiplexer
                .Connect(configuration["REDIS_CONNECTION"] ?? "localhost:6379")
                .GetDatabase();
            await redisDb.KeyDeleteAsync($"session:{sessionId}");
        }

        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return RedirectToAction("Login");
    }
}
