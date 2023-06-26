using Session5.Context;
using Session5.Model.Users;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ASPWebAPI.Repository
{
    public class AuthManger : IAuthManager
    {
        readonly UserManager<APIUser> _userManager;
        readonly IMapper _mapper;
        readonly IConfiguration _configuration;
        public APIUser _user;
        private const string _loginProvider = "ProductApi";
        private string _refreshToken = "RefreshToken";
        //constructor
        public AuthManger(UserManager<APIUser> userManager, IMapper mapper, IConfiguration configuration)
        {
            _userManager = userManager;
            _mapper = mapper;
            _configuration = configuration;
        }

        public async Task<AuthresponseDto> Login(LoginDto loginDto)
        {
            #region oldcode 
            //bool isValidUser = false;

            //var user = await _userManager.FindByEmailAsync(logindto.Email);
            //if (user == null)
            //{
            //    return default;
            //}
            //isValidUser = await _userManager.CheckPasswordAsync(user, logindto.Password);


            //return isValidUser;
            #endregion
            _user = await _userManager.FindByEmailAsync(loginDto.Email);
            bool isValidUser = await _userManager.CheckPasswordAsync(_user, loginDto.Password);
            if (_user == null || isValidUser == false)
            {
                return null;
            }
            var token = await GenerateToken();
            return new AuthresponseDto
            {
                Token = token,
                UserId = _user.Id,
                RefreshToken = await CraeteRefreshToken()


            };

        }

        private async Task<string> GenerateToken()
        {
            #region OldCode
            //Claims
            //var userClaims = new Claim[] { };
            ////Roles, SecretKey, signthe Token
            //var userSecurityKey = Encoding.UTF8.GetBytes("asjlalkdjhddkhdhdddhhdd");
            //var userSymmetricSecurity=new SymmetricSecurityKey(userSecurityKey);
            //var userSigninCredentials = new SigningCredentials(userSymmetricSecurity, SecurityAlgorithms.HmacSha256);
            //var userJwtSecurityToken = new JwtSecurityToken(
            //    issuer: "",
            //    audience: "",
            //    expires: DateTime.Now.AddMinutes(10),
            //    signingCredentials: userSigninCredentials,
            //    claims: userClaims);
            #endregion

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSetting:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var roles = await _userManager.GetRolesAsync(_user);
            var roleClaims = roles.Select(x => new Claim(ClaimTypes.Role, x)).ToList();
            var userClaims = await _userManager.GetClaimsAsync(_user);

            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub,_user.Email),
                 new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                 new Claim(JwtRegisteredClaimNames.Email,_user.Email),
                 new Claim("uid",_user.Id)

            }
            .Union(userClaims).Union(roleClaims);
            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSetting:Issuer"],
                audience: _configuration["JwtSetting:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToInt64(_configuration["JwtSetting:DurationInMinutes"])),
                signingCredentials: credentials
                );
            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        public async Task<IEnumerable<IdentityError>> RegisterUser(APIUserDto userDto)
        {
            var user = _mapper.Map<APIUser>(userDto);
            user.UserName = userDto.Email;
            var result = await _userManager.CreateAsync(user, userDto.Password);
            if (result.Succeeded)
            {
                _userManager.AddToRoleAsync(user, "User");
            }
            return result.Errors;
        }

        public async Task<string> CraeteRefreshToken()
        {
            await _userManager.RemoveAuthenticationTokenAsync(_user, _loginProvider, _refreshToken);
            var newrefreshToken = await _userManager.GenerateUserTokenAsync(_user, _loginProvider, _refreshToken);
            var result = await _userManager.SetAuthenticationTokenAsync(_user, _loginProvider, _refreshToken, newrefreshToken);
            return newrefreshToken;
        }

        public async Task<AuthresponseDto> VerifyRefreshToken(AuthresponseDto request)
        {
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenContent = jwtSecurityTokenHandler.ReadJwtToken(request.Token);
            var userName = tokenContent.Claims.ToList().FirstOrDefault(t => t.Type == JwtRegisteredClaimNames.Email)?.Value;
            _user = await _userManager.FindByNameAsync(userName);
            if (_user == null || _user.Id != request.UserId)
            {
                return null;

            }
            var isValidRefreshToken = await _userManager.VerifyUserTokenAsync(_user, _loginProvider, _refreshToken, request.RefreshToken);
            if (isValidRefreshToken)
            {
                var token = await GenerateToken();
                return new AuthresponseDto
                {
                    Token = token,
                    UserId = _user.Id,
                    RefreshToken = await CraeteRefreshToken()
                };
            }
            //await _userManager.UpdateSecurityStampAsync(_user);
            return null;
        }
    }
}
