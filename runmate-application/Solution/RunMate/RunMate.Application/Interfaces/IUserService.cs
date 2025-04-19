using RunMate.RunMate.Application.DTOs.UserDTOs;

namespace RunMate.RunMate.Application.Interfaces
{
    public interface IUserService
    {
        Task<IEnumerable<UserDto>> GetAllUsersAsync();
        Task<UserDto> GetUserByIdAsync(Guid id);
        Task<UserDto> GetUserByUsernameAsync(string username);
        Task<bool> CreateUserAsync(RegisterUserDto userDto);
        Task<bool> DeleteUserAsync(Guid id);
        Task<bool> ChangePasswordAsync(Guid id, ChangePasswordDto passwordDto);
        Task<bool> ToggleUserStatusAsync(Guid id);
    }
}
