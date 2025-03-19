using AuthService.Authorization;
using AuthService.Data;
using AuthService.Middleware;
using AuthService.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using static AuthService.Authorization.AuthClaims;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var env = builder.Environment;

// Configure Services
ConfigureServices(builder.Services, config);

var app = builder.Build();

// Apply Migrations & Seed Data
await ApplyMigrationsAndSeedData(app, env);

// Configure Middleware & Pipeline
ConfigureMiddleware(app, env);

app.Run();


// Configure Services Method
void ConfigureServices(IServiceCollection services, IConfiguration config)
{
    // Database Configuration
    services.AddDbContext<AuthDbContext>(options =>
        options.UseInMemoryDatabase("AuthDb")
    );

    // Caching & JWT Handler
    services.AddMemoryCache();
    services.AddSingleton<JwtSecurityTokenHandler>();

    // Application Services
    services.AddScoped<JwtService>();
    services.Configure<JwtOptions>(config.GetSection("Jwt"));
    services.Configure<CacheSettings>(config.GetSection("CacheSettings"));

    // Authentication & JWT Configuration
    var jwtOptions = GetJwtOptions(config);

    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.RequireHttpsMetadata = false;
            options.SaveToken = true;
            options.TokenValidationParameters = JwtTokenValidationHelper.GetValidationParameters(jwtOptions);
        });

    // Authorization Policies
    services.AddAuthorization(options =>
    {
        foreach (var permission in Permissions.AllPermissions)
        {
            options.AddPolicy(permission, policy => policy.Requirements.Add(new PermissionRequirement(permission)));
        }
    });

    services.AddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
    services.AddSingleton<IAuthorizationHandler, PermissionAuthorizationHandler>();

    // Controllers & Swagger
    services.AddControllers();
    services.AddEndpointsApiExplorer();

    if (config.GetValue<bool>("EnableSwagger"))
    {
        ConfigureSwagger(services);
    }
}

// Apply Migrations & Seed Data Method
async Task ApplyMigrationsAndSeedData(WebApplication app, IWebHostEnvironment env)
{
    using var scope = app.Services.CreateScope();
    var services = scope.ServiceProvider;
    var logger = services.GetRequiredService<ILogger<Program>>();

    try
    {
        var context = services.GetRequiredService<AuthDbContext>();

        if (env.IsProduction())
        {
            // context.Database.Migrate(); // Uncomment when using real DB
        }

        await DataSeeder.SeedAsync(services, logger);
        logger.LogInformation("Database seeding completed successfully.");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred while seeding the database.");
    }
}

// Configure Middleware Method
void ConfigureMiddleware(WebApplication app, IWebHostEnvironment env)
{
    if (config.GetValue<bool>("EnableSwagger"))
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    if (!env.IsDevelopment())
    {
        app.UseExceptionHandler("/error");
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseRouting();

    app.UseAuthentication();
    app.UseMiddleware<TokenRefreshMiddleware>();
    app.UseAuthorization();

    app.MapControllers();
}
JwtOptions GetJwtOptions(IConfiguration config)
{
    var options = config.GetSection("Jwt").Get<JwtOptions>();
    if (options == null || string.IsNullOrWhiteSpace(options.Secret))
    {
        throw new InvalidOperationException("JWT configuration is missing or invalid.");
    }
    return options;
}
void ConfigureSwagger(IServiceCollection services)
{
    services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new OpenApiInfo
        {
            Title = "Auth API",
            Version = "v1",
            Description = "Authentication API with JWT and Role-based Authorization"
        });

        // 🔹 Add JWT Authentication to Swagger
        c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
        {
            Name = "Authorization",
            Type = SecuritySchemeType.Http,
            Scheme = "Bearer",
            BearerFormat = "JWT",
            In = ParameterLocation.Header,
            Description = "Enter JWT token in the format: Bearer {your_token}"
        });

        c.AddSecurityRequirement(new OpenApiSecurityRequirement
        {
            {
                new OpenApiSecurityScheme
                {
                    Reference = new OpenApiReference
                    {
                        Type = ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    }
                },
                Array.Empty<string>()
            }
        });

        // Include XML comments (if available)
        var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
        var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
        if (File.Exists(xmlPath))
        {
            c.IncludeXmlComments(xmlPath);
        }
    });
}
