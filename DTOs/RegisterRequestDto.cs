namespace AuthService.DTOs;

public class RegisterRequestDto
{
    public required string Email { get; set; }
    public required string Password { get; set; }
    public List<string> Roles { get; set; } = new();
}
