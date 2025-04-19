using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace RunMate.Shared.Auth;

public static class JwtAuthExtensions
{
    public static IServiceCollection AddSharedJwtAuthentication(
this IServiceCollection services,
IConfiguration configuration)
    {
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = configuration["Jwt:Issuer"],
                ValidAudience = configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(configuration["Jwt:Key"])),
                // Adicione mapeamento de claims
                NameClaimType = "unique_name",
                RoleClaimType = "role"
            };
        });

        return services;
    }
}

public static class ClaimsPrincipalExtensions
{
    public static string GetUserId(this System.Security.Claims.ClaimsPrincipal user)
    {
        return user.FindFirst("nameid")?.Value;
    }

    public static string GetUserName(this System.Security.Claims.ClaimsPrincipal user)
    {
        return user.FindFirst("unique_name")?.Value;
    }

    public static string GetUserEmail(this System.Security.Claims.ClaimsPrincipal user)
    {
        return user.FindFirst("email")?.Value;
    }

    public static string GetUserRole(this System.Security.Claims.ClaimsPrincipal user)
    {
        return user.FindFirst("role")?.Value;
    }
}