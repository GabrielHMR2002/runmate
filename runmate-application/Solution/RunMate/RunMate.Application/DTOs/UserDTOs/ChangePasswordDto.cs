using System.ComponentModel.DataAnnotations;

namespace RunMate.RunMate.Application.DTOs.UserDTOs
{
    public class ChangePasswordDto
    {
        [Required(ErrorMessage = "A senha atual é obrigatória")]
        public string CurrentPassword { get; set; }

        [Required(ErrorMessage = "A nova senha é obrigatória")]
        [StringLength(100, MinimumLength = 6, ErrorMessage = "A senha deve ter pelo menos 6 caracteres")]
        public string NewPassword { get; set; }

        [Compare("NewPassword", ErrorMessage = "As senhas não coincidem")]
        public string ConfirmNewPassword { get; set; }
    }
}
