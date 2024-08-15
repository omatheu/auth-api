using System.ComponentModel.DataAnnotations;

namespace AuthenticationAuthotization.Models
{
    public class InboundUser
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
