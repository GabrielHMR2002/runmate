using Microsoft.EntityFrameworkCore;
using RunMate.Domain.Entities;
using RunMate.RunMate.Application.DTOs.UserDTOs;
using RunMate.RunMate.Application.Interfaces;
using RunMate.RunMate.Infrastructure.Persistence;

namespace RunMate.RunMate.Application.Services
{
    public class UserService : IUserService
    {
        private readonly RunMateContext _context;
        private readonly IAuthService _authService;

        public UserService(RunMateContext context, IAuthService authService)
        {
            _context = context;
            _authService = authService;
        }

        public async Task<IEnumerable<UserDto>> GetAllUsersAsync()
        {
            var users = await _context.Users.ToListAsync();
            return users.Select(MapToDto);
        }

        public async Task<UserDto> GetUserByIdAsync(Guid id)
        {
            var user = await _context.Users.FindAsync(id);
            return user != null ? MapToDto(user) : null;
        }

        public async Task<UserDto> GetUserByUsernameAsync(string username)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
            return user != null ? MapToDto(user) : null;
        }

        public async Task<bool> CreateUserAsync(RegisterUserDto userDto)
        {
            // Verificar se o usuário já existe
            if (await _context.Users.AnyAsync(u => u.Username == userDto.Username || u.Email == userDto.Email))
            {
                return false;
            }

            var user = new User
            {
                Id = Guid.NewGuid(),
                Username = userDto.Username,
                Email = userDto.Email,
                FullName = userDto.FullName,
                BirthDate = userDto.BirthDate,
                PasswordHash = _authService.HashPassword(userDto.Password),
                Role = RunMate.Domain.Enums.UserRole.User,
                CreatedAt = DateTime.UtcNow,
                IsActive = true
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();
            return true;
        }

        //public async Task<bool> UpdateUserAsync(Guid id, UpdateUserDto userDto)
        //{
        //    var user = await _context.Users.FindAsync(id);
        //    if (user == null)
        //    {
        //        return false;
        //    }

        //    // Verificar se o email já está em uso por outro usuário
        //    if (!string.IsNullOrEmpty(userDto.Email) && userDto.Email != user.Email)
        //    {
        //        if (await _context.Users.AnyAsync(u => u.Email == userDto.Email && u.Id != id))
        //        {
        //            return false;
        //        }
        //        user.Email = userDto.Email;
        //    }

        //    if (!string.IsNullOrEmpty(userDto.FullName))
        //    {
        //        user.FullName = userDto.FullName;
        //    }

        //    if (userDto.BirthDate.HasValue)
        //    {
        //        user.BirthDate = userDto.BirthDate.Value;
        //    }

        //    if (userDto.Role.HasValue)
        //    {
        //        user.Role = userDto.Role.Value;
        //    }

        //    if (userDto.IsActive.HasValue)
        //    {
        //        user.IsActive = userDto.IsActive.Value;
        //    }

        //    user.UpdatedAt = DateTime.UtcNow;
        //    await _context.SaveChangesAsync();
        //    return true;
        //}

        public async Task<bool> DeleteUserAsync(Guid id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return false;
            }

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ChangePasswordAsync(Guid id, ChangePasswordDto passwordDto)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return false;
            }

            // Verificar se a senha atual está correta
            if (!_authService.VerifyPassword(passwordDto.CurrentPassword, user.PasswordHash))
            {
                return false;
            }

            user.PasswordHash = _authService.HashPassword(passwordDto.NewPassword);
            user.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<bool> ToggleUserStatusAsync(Guid id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
            {
                return false;
            }

            user.IsActive = !user.IsActive;
            user.UpdatedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }

        private UserDto MapToDto(User user)
        {
            return new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                FullName = user.FullName,
                BirthDate = user.BirthDate,
                Role = user.Role,
                CreatedAt = user.CreatedAt,
                UpdatedAt = user.UpdatedAt,
                LastLogin = user.LastLogin,
                IsActive = user.IsActive
            };
        }
    }
}
