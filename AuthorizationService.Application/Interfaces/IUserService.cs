using AuthorizationService.Domain.Models;

namespace AuthorizationService.Application.Interfaces
{
    public interface IUserService
    {
        Task<bool> RegisterUserAsync(User user, string password);
        Task<User?> ValidateUserAsync(string username, string password);
        string GenerateJwtToken(User user);
        Task<Role?> GetRoleByIdAsync(int roleId);
    }
}

