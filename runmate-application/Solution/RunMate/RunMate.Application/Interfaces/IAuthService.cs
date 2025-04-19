using RunMate.Domain.Entities;
using RunMate.RunMate.Application.DTOs;

namespace RunMate.RunMate.Application.Interfaces
{
    public interface IAuthService
    {
        Task<LoginResponseDto> Login(LoginRequestDto request);
        string GenerateJwtToken(User user);
        string HashPassword(string password);
        bool VerifyPassword(string password, string passwordHash);
    }
}
