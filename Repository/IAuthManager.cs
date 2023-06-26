using Session5.Model.Users;
using Microsoft.AspNetCore.Identity;

namespace ASPWebAPI.Repository
{
    public interface IAuthManager
    {
        Task<IEnumerable<IdentityError>> RegisterUser(APIUserDto userDto);
        Task<AuthresponseDto> Login(LoginDto loginDto);

        Task<string> CraeteRefreshToken();
        Task<AuthresponseDto> VerifyRefreshToken(AuthresponseDto request);
    }
}
