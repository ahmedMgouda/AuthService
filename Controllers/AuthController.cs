using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authorization;
using AuthService.Data;
using AuthService.DTOs;
using AuthService.Models;
using static AuthService.Authorization.AuthClaims;
using AuthService.Services;

namespace AuthService.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly AuthDbContext _dbContext;
    private readonly JwtService _jwtService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(AuthDbContext dbContext, JwtService jwtService, ILogger<AuthController> logger)
    {
        _dbContext = dbContext;
        _jwtService = jwtService;
        _logger = logger;
    }
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterRequestDto request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        string normalizedEmail = request.Email.Trim().ToLower();

        if (await _dbContext.Users.AnyAsync(u => u.Email == normalizedEmail))
        {
            _logger.LogWarning("Registration attempt with existing email: {Email}", normalizedEmail);
            return Conflict(new { message = "Email is already registered." });
        }

        // Retrieve the standard user role
        var standardRole = await _dbContext.Roles.FirstOrDefaultAsync(r => r.Name == Roles.StandardUser);
        if (standardRole == null)
        {
            _logger.LogError("Standard user role not found. Ensure roles are seeded in the database.");
            return StatusCode(500, new { message = "User role configuration error." });
        }

        var user = new User
        {
            Email = normalizedEmail,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password),
            UserRoles = new List<UserRole>
            {
                new UserRole { RoleId = standardRole.Id }
            }
        };

        _dbContext.Users.Add(user);
        await _dbContext.SaveChangesAsync();

        _logger.LogInformation("New user registered with standard role: {Email}", normalizedEmail);
        return CreatedAtAction(nameof(Register), new { message = "User registered successfully." });
    }


    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        string normalizedEmail = request.Email.Trim().ToLower();

        var user = await _dbContext.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail);
        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            _logger.LogWarning("Invalid login attempt for email: {Email}", normalizedEmail);
            return Unauthorized(new { message = "Invalid email or password." });
        }

        var accessToken = await _jwtService.GenerateJwtAsync(user);
        var refreshToken = await _jwtService.GenerateRefreshTokenAsync(user);

        _logger.LogInformation("User logged in: {Email}", normalizedEmail);
        return Ok(new AuthResponseDto
        {
            Token = accessToken,
            RefreshToken = refreshToken
        });
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequestDto refreshRequest)
    {
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var user = await _jwtService.ValidateRefreshTokenAsync(refreshRequest.RefreshToken);
        if (user == null)
            return Unauthorized(new { message = "Invalid or expired refresh token." });

        // Generate new tokens
        var newAccessToken = await _jwtService.GenerateJwtAsync(user);
        var newRefreshToken = await _jwtService.GenerateRefreshTokenAsync(user);

        _logger.LogInformation("Refresh token renewed for user: {Email}", user.Email);
        return Ok(new AuthResponseDto
        {
            Token = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }

    [Authorize]
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _dbContext.Users
            .Select(u => new { u.Id, u.Email })
            .ToListAsync();

        return Ok(users);
    }

    /// <summary>
    /// Updates the user's claims version when their role or permissions change.  
    /// This forces a token refresh to ensure the user obtains the latest claims.  
    /// </summary>
    [Authorize]
    [HttpGet("refresh-claims-version")]
    public async Task<IActionResult> RefreshClaimsVersion(int id = 1)
    {

        // Update role or permission 

        await _jwtService.UpdateClaimsVersion(id);
        return Ok();
    }

}
