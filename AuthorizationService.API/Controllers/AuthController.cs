using AuthorizationService.API.Requests;
using AuthorizationService.Application.Interfaces;
using AuthorizationService.Domain.Models;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationService.API.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IUserService _userService;

        public AuthController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterUserRequest request)
        {

            if (!Enum.TryParse<UserRole>(request.Role, true, out var role))
                return BadRequest("Invalid role specified.");

            // Преобразуем enum в ID роли
            int roleId = (int)role;

            // Проверяем, существует ли роль в базе данных
            var roleExist = await _userService.GetRoleByIdAsync(roleId);
            if (roleExist == null)
                return BadRequest($"Role '{request.Role}' does not exist.");

            // Создаём нового пользователя
            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PhoneNumber = request.PhoneNumber,
                RoleId = roleId
            };

            var result = await _userService.RegisterUserAsync(user, request.Password);

            if (!result)
                return BadRequest("User already exists.");

            return Ok("User registered successfully.");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Проверка пользователя
            var user = await _userService.ValidateUserAsync(request.Username, request.Password);
            if (user == null)
                return Unauthorized();

            // Генерация токена
            var token = _userService.GenerateJwtToken(user);
            return Ok(new { Token = token });
        }
    }
}

