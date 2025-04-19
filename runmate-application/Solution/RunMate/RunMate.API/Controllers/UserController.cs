using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RunMate.Domain.Entities;
using RunMate.RunMate.Application.DTOs.UserDTOs;
using RunMate.RunMate.Application.Interfaces;
using System.Security.Claims;

namespace RunMate.RunMate.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _userService;

        public UsersController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _userService.GetAllUsersAsync();
            return Ok(users);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetUserById(Guid id)
        {
            // Verificar se o usuário está tentando acessar seus próprios dados ou é um admin
            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var isAdmin = User.IsInRole("Admin");

            if (!isAdmin && currentUserId != id.ToString())
            {
                return Forbid();
            }

            var user = await _userService.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        [HttpGet("username/{username}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> GetUserByUsername(string username)
        {
            var user = await _userService.GetUserByUsernameAsync(username);
            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> CreateUser([FromBody] RegisterUserDto userDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _userService.CreateUserAsync(userDto);
            if (!result)
            {
                return BadRequest(new { message = "Nome de usuário ou email já existe" });
            }

            return CreatedAtAction(nameof(GetUserByUsername), new { username = userDto.Username }, null);
        }

        //[HttpPut("{id}")]
        //public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserDto userDto)
        //{
        //    if (!ModelState.IsValid)
        //    {
        //        return BadRequest(ModelState);
        //    }

        //    // Verificar se o usuário está tentando atualizar seus próprios dados ou é um admin
        //    var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        //    var isAdmin = User.IsInRole("Admin");

        //    if (!isAdmin && currentUserId != id.ToString())
        //    {
        //        return Forbid();
        //    }

        //    // Se não for admin, não pode alterar o Role ou IsActive
        //    if (!isAdmin)
        //    {
        //        userDto.Role = null;
        //        userDto.IsActive = null;
        //    }

        //    var result = await _userService.UpdateUserAsync(id, userDto);
        //    if (!result)
        //    {
        //        return BadRequest(new { message = "Não foi possível atualizar o usuário. Verifique se o email já está em uso." });
        //    }

        //    return NoContent();
        //}

        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            var result = await _userService.DeleteUserAsync(id);
            if (!result)
            {
                return NotFound();
            }

            return NoContent();
        }

        [HttpPut("{id}/change-password")]
        public async Task<IActionResult> ChangePassword(Guid id, [FromBody] ChangePasswordDto passwordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Verificar se o usuário está tentando alterar sua própria senha
            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (currentUserId != id.ToString())
            {
                return Forbid();
            }

            var result = await _userService.ChangePasswordAsync(id, passwordDto);
            if (!result)
            {
                return BadRequest(new { message = "Senha atual incorreta" });
            }

            return NoContent();
        }

        [HttpPut("{id}/toggle-status")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> ToggleUserStatus(Guid id)
        {
            var result = await _userService.ToggleUserStatusAsync(id);
            if (!result)
            {
                return NotFound();
            }

            return NoContent();
        }

        [HttpGet("me")]
        public async Task<IActionResult> GetCurrentUser()
        {
            var currentUserId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(currentUserId) || !Guid.TryParse(currentUserId, out var userId))
            {
                return Unauthorized();
            }

            var user = await _userService.GetUserByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }
    }
}
