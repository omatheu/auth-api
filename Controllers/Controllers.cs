using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationAuthotization.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class HomeController : ControllerBase
    {
        public HomeController()
        {
        }

        // api/home
        [HttpGet]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = nameof(RoleTypes.User))]
        public IActionResult Health()
        {
            return Ok("Api is fine");
        }

        // api/home/admin
        [HttpGet("admin")]
        [Authorize(AuthenticationSchemes = "Bearer", Roles = nameof(RoleTypes.Admin))]
        public IActionResult AdminRoute()
        {
            return Ok("Admin route");
        }
    }
}
