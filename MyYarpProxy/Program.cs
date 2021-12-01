using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Configure CORS
var corsPolicyName = "CorsPolicy";
builder.Services.AddCors(options =>
{
    options.AddPolicy(corsPolicyName, policy =>
    {
        // App:CorsOrigins in appsettings.json can contain more than one address separated by comma.
        policy
          .WithOrigins(
            builder.Configuration["CorsOrigins"]
              .Split(",", StringSplitOptions.RemoveEmptyEntries)
              .ToArray())
          .SetPreflightMaxAge(TimeSpan.FromDays(1))
          .SetIsOriginAllowedToAllowWildcardSubdomains()
          .AllowAnyHeader()
          .AllowAnyMethod()
          .AllowCredentials();
    });
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var resourceRoleClaimName = $"role/resource/{builder.Configuration["Jwt:Audience"]}";
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(o =>
{
    o.Authority = builder.Configuration["Jwt:Authority"];
    o.Audience = builder.Configuration["Jwt:Audience"];
    o.TokenValidationParameters = new TokenValidationParameters
    {
        ClockSkew = TimeSpan.FromSeconds(Convert.ToDouble(builder.Configuration["Jwt:ClockSkew"]))
    };
    o.RequireHttpsMetadata = false;
    o.TokenValidationParameters = new TokenValidationParameters
    {
        // Keycloak默认会把First Name和Last Name组合成Name放到Name Claim中, 如果要使用Username, 可以添加下面的代码.
        NameClaimType = "preferred_username"
    };
    o.Events = new JwtBearerEvents
    {
        OnTokenValidated = context => {
            var identity = context.Principal?.Identity as ClaimsIdentity;
            var jsonDocumentOptions = new JsonDocumentOptions
            {
                AllowTrailingCommas = true
            };
            var realmAccess = context.Principal?.Claims.FirstOrDefault(p => p.Type == "realm_access");
            if (realmAccess?.Value != null)
            {
                using JsonDocument document = JsonDocument.Parse(realmAccess.Value, jsonDocumentOptions);
                if (document.RootElement.TryGetProperty("roles", out var elementRoles))
                {
                    foreach (var elementRole in elementRoles.EnumerateArray())
                    {
                        var role = elementRole.GetString();
                        if (role != null) identity?.AddClaim(new Claim("role/realm", role));
                    }
                }
            }

            var resourceAccess = context.Principal?.Claims.FirstOrDefault(p => p.Type == "resource_access");
            if (resourceAccess?.Value != null)
            {
                using JsonDocument document = JsonDocument.Parse(resourceAccess.Value, jsonDocumentOptions);
                if (document.RootElement.TryGetProperty("webapi", out var elementWebAPI))
                {
                    if (elementWebAPI.TryGetProperty("roles", out var elementRoles))
                    {
                        foreach (var elementRole in elementRoles.EnumerateArray())
                        {
                            var role = elementRole.GetString();
                            if (role != null) identity?.AddClaim(new Claim(resourceRoleClaimName, role));
                        }
                    }
                }
            }
            return Task.CompletedTask;
        }
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("users", policy => policy.RequireClaim(resourceRoleClaimName, "user"));
    options.AddPolicy("admins", policy => policy.RequireClaim(resourceRoleClaimName, "admin"));
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseRouting();

// Enable CORS!
app.UseCors(corsPolicyName);

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Register the reverse proxy routes
app.UseEndpoints(endpoints =>
{
    endpoints.MapReverseProxy();
});
//app.MapReverseProxy();

app.Run();
