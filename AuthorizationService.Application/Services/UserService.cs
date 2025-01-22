
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthorizationService.Application.Interfaces;
using AuthorizationService.Domain.Models;
using AuthorizationService.Infrastructure.EntityFramework;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

public class UserService : IUserService
{
    private readonly ApplicationDbContext _context;
    private readonly ITokenService _tokenService;
    private readonly IConfiguration _configuration;

    public UserService(ApplicationDbContext context, IConfiguration configuration, ITokenService tokenService)
    {
        _context = context;
        _configuration = configuration;
        _tokenService = tokenService;
    }


    public async Task<bool> RegisterUserAsync(User user, string password)
    {
        // Проверка существующего пользователя
        if (_context.Users.Any(u => u.Username == user.Username || u.Email == user.Email))
            return false;

        // Генерация хеша пароля 
        user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(password);

        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return true;
    }

    public async Task<User?> ValidateUserAsync(string username, string password)
    {
        var user = await _context.Users.Include(u => u.Role).FirstOrDefaultAsync(u => u.Username == username);
        if (user == null || !BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            return null;

        return user;
    }

    public string GenerateJwtToken(User user) => _tokenService.GenerateJwtToken(user);

    public async Task<Role?> GetRoleByIdAsync(int roleId)
    {
        return await _context.Roles.FirstOrDefaultAsync(r => r.Id == roleId);
    }

}
