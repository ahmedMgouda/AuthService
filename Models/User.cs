namespace AuthService.Models;

public class User
{
    public int Id { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public Guid ClaimsVersion { get; set; } = Guid.NewGuid();
    public List<UserRole> UserRoles { get; set; } = new(); 
}


