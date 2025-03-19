namespace AuthService.Models;

public class RefreshToken
{
    public Guid Id { get; set; }
    public int UserId { get; set; }
    public DateTime ExpirationDate { get; set; }
    public bool IsRevoked { get; set; } = false;
    public DateTime? RevokedAt { get; set; }
    public DateTime CreatedAt { get; set; }
    public User User { get; set; }
}
