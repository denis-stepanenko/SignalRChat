using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using SignalRChat.Hubs;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSignalR();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => options.LoginPath = "/login");
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapHub<ChatHub>("/chat");

var users = new List<User>
{
    new User("dennis", "12345", new Role("user")),
    new User("andrew", "12345", new Role("user"))
};

app.MapPost("/login", async (string? url, HttpContext context) =>
{
    var form = context.Request.Form;

    if (!form.ContainsKey("login") || !form.ContainsKey("password"))
        return Results.BadRequest("Login or password is not sent");

    if (string.IsNullOrEmpty(form["login"]) || string.IsNullOrEmpty(form["password"]))
        return Results.BadRequest("Login or password is not set");

    string email = form["login"];
    string password = form["password"];

    var user = users.Where(x => x.Login == email && x.Password == password).FirstOrDefault();

    if (user is null)
        return Results.Unauthorized();

    var claims = new List<Claim>
    {
        new Claim(ClaimsIdentity.DefaultNameClaimType, user.Login),
        new Claim(ClaimsIdentity.DefaultRoleClaimType, user.Role.Name)
    };
    var claimsIdentity = new ClaimsIdentity(claims, "Cookies");
    var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
    await context.SignInAsync(claimsPrincipal);

    return Results.Redirect(url ?? "/");
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

app.MapGet("/", [Authorize] async (HttpContext context) =>
{
    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.SendFileAsync("html/index.html");
});

app.MapGet("/login", async (HttpContext context) =>
{
    context.Response.ContentType = "text/html; charset=utf-8";
    await context.Response.SendFileAsync("html/login.html");
});

app.Run();

record class Role(string Name);
record class User(string Login, string Password, Role Role);
