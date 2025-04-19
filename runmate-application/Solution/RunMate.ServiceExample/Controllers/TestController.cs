using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RunMate.ServiceExample.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult GetPublic()
        {
            return Ok(new { message = "Este é um endpoint público" });
        }

        [HttpGet("protected")]
        [Authorize]
        public IActionResult GetProtected()
        {
            // Use os nomes corretos das claims conforme mapeados pelo sistema
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var username = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
            var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
            var role = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;

            // Alternativa: use as constantes do ClaimTypes
            // var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            // var username = User.FindFirst(ClaimTypes.Name)?.Value;
            // var email = User.FindFirst(ClaimTypes.Email)?.Value;
            // var role = User.FindFirst(ClaimTypes.Role)?.Value;

            return Ok(new
            {
                message = "Este é um endpoint protegido",
                userId,
                username,
                email,
                role
            });
        }

        [HttpGet("claims")]
        [Authorize]
        public IActionResult GetClaims()
        {
            var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
            return Ok(new { claims });
        }
    }
}