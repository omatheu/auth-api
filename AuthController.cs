using AuthenticationAuthotization.Models;
using AuthenticationAuthotization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationAuthorization
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;

        public AuthController(UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _signInManager = signInManager;
        }

        //auth/create
        [HttpPost("create")]
        public async Task<IActionResult> CreateUser([FromBody] InboundUser inboundUser)
        {
            try
            {
                var user = new IdentityUser { UserName = inboundUser.Email };

                bool userRoleExists = await _roleManager.RoleExistsAsync(RoleTypes.User.ToString());

                if (!userRoleExists)
                {
                    await _roleManager.CreateAsync(new IdentityRole("User"));
                }

                var result = await _userManager.CreateAsync(user, inboundUser.Password);
                await _userManager.AddToRoleAsync(user, "User");

                var errors = result.Errors.Select(e => e.Description);

                if (result.Succeeded)
                {
                    var token = await BuildToken(inboundUser, new[] { RoleTypes.User });
                    return Ok(token);
                }
                else
                {
                    return BadRequest(errors);
                }
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        //auth/admin/create
        [HttpPost("admin/create")]
        public async Task<IActionResult> CreateAdmin([FromBody] InboundUser inboundUser)
        {
            try
            {
                var user = new IdentityUser { UserName = inboundUser.Email, Email = inboundUser.Email };

                var x = RoleTypes.Admin.ToString();

                bool userRoleExists = await _roleManager.RoleExistsAsync(RoleTypes.Admin.ToString());

                if (!userRoleExists)
                {
                    await _roleManager.CreateAsync(new IdentityRole(RoleTypes.Admin.ToString()));
                }

                var result = await _userManager.CreateAsync(user, inboundUser.Password);
                await _userManager.AddToRoleAsync(user, RoleTypes.Admin.ToString());

                var errors = result.Errors.Select(e => e.Description);

                if (result.Succeeded)
                {
                    var token = await BuildToken(inboundUser, new[] { RoleTypes.Admin });
                    if (token == null) return BadRequest("Email or password invalid!");
                    return Ok(token);
                }
                else
                {
                    return BadRequest(errors);
                }
            }
            catch (Exception e)
            {
                return BadRequest(e.Message);
            }
        }

        [HttpPost("admin/login")]
        public async Task<IActionResult> LoginAdmin([FromBody] InboundUser userInfo)
        {
            var result = await _signInManager.PasswordSignInAsync(userInfo.Email, userInfo.Password,
             isPersistent: false, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                var token = await BuildToken(userInfo, new[] { RoleTypes.Admin, RoleTypes.User });

                if (token == null) return BadRequest("Email or password invalid!");

                return Ok(token);
            }
            else
            {
                return BadRequest("Email or password invalid!");
            }
        }

        //auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] InboundUser userInfo)
        {
            var result = await _signInManager.PasswordSignInAsync(userInfo.Email, userInfo.Password,
                 isPersistent: false, lockoutOnFailure: false);

            if (result.Succeeded)
            {
                var token = await BuildToken(userInfo, new[] { RoleTypes.User });
                return Ok(token);
            }
            else
            {
                return BadRequest("Email or password invalid!");
            }
        }

        private async Task<string?> BuildToken(InboundUser userInfo, RoleTypes[] roleTypes)
        {
            // Check if user exists
            var user = await _userManager.FindByEmailAsync(userInfo.Email);
            if (user == null) return null;

            // Here, we'll use some claims to define
            // There claims refers to what kind of permissions this token will have
            // In this example, the token will contain the information of Email and
            // a Jti, an unique identifier for the JWT
            var claims = new List<Claim>() {
                new Claim(JwtRegisteredClaimNames.Email, userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Define the roles of this token based in a array of parameters
            foreach (var role in roleTypes)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
            }

            // Find all the roles that the user has
            var userRoles = await _userManager.GetRolesAsync(user);

            // Add all the roles to the claims that will be used to generate
            // the token permissions
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            // Generate the key
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:key"]));
            // Generate the credentials
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            // Expiration time of token
            var expiration = DateTime.UtcNow.AddHours(1);

            // And generate the token, passing the claims
            JwtSecurityToken token = new JwtSecurityToken(
                issuer: null,
                audience: null,
                claims: claims,
                expires: expiration,
                signingCredentials: creds
            );

            // And finnaly returns the token
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}