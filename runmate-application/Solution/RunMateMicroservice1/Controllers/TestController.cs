using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RunMate.Shared.Auth;

namespace RunMateMicroservice1.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult GetPublic()
        {
            return Ok(new { message = "Este é um endpoint público que qualquer um pode acessar" });
        }

        [HttpGet("protected")]
        [Authorize] // Este endpoint requer autenticação
        public IActionResult GetProtected()
        {
            // Obtenha informações do usuário autenticado
            var userId = User.GetUserId();
            var username = User.GetUserName();
            var role = User.GetUserRole();

            return Ok(new
            {
                message = "Este é um endpoint protegido - você está autenticado!",
                userId,
                username,
                role
            });
        }

        [HttpGet("admin")]
        [Authorize(Roles = "Admin")] // Este endpoint requer papel de Admin
        public IActionResult GetAdmin()
        {
            return Ok(new { message = "Este é um endpoint apenas para administradores" });
        }
    }
}