using RunMate.RunMate.Domain.Enums;
using System.Reflection;

namespace RunMate.Domain.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string Username { get; set; }
        public string PasswordHash { get; set; }
        public string Email { get; set; }
        public string FullName { get; set; }
        public DateTime BirthDate { get; set; }
        public UserRole Role { get; set; } = UserRole.User;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? UpdatedAt { get; set; }
        public DateTime? LastLogin { get; set; } 
        public bool IsActive { get; set; } = true; 
        public string? RefreshToken { get; set; } 
        public DateTime? RefreshTokenExpiryTime { get; set; } 
    }
}
