using Microsoft.AspNetCore.Mvc;
using RunMate.RunMate.Application.DTOs;
using RunMate.RunMate.Application.DTOs.UserDTOs;
using RunMate.RunMate.Application.Interfaces;

namespace RunMate.RunMate.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;

        public AuthController(IAuthService authService, IUserService userService)
        {
            _authService = authService;
            _userService = userService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var response = await _authService.Login(request);

            if (response == null)
            {
                return Unauthorized(new { message = "Nome de usuário ou senha inválidos" });
            }

            return Ok(response);
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var result = await _userService.CreateUserAsync(request);

            if (!result)
            {
                return BadRequest(new { message = "Nome de usuário ou email já existe" });
            }

            return Ok(new { message = "Usuário registrado com sucesso" });
        }
    }
}
