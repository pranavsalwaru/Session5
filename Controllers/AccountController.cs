using Session5.Model.Users;
using Session5.Repository;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

{
    /* [Route("api/[controller]")]
     [ApiController]
     public class AccountController : ControllerBase
     {
         readonly IAuthManager _authManager;

         public AccountController(IAuthManager authManager)
         {
             _authManager = authManager;

         }

         [HttpPost]
         [Route("register")]
         public async Task<ActionResult> Register(APIUserDto aPIUserDto)
         {
             var errors = await _authManager.RegisterUser(aPIUserDto);
             if (errors.Any())
             {
                 foreach (var error in errors)
                 {
                     ModelState.AddModelError(error.Code, error.Description);
                 }
                 return BadRequest();
             }
             return Ok();
         }
         [HttpPost]
         public async Task<ActionResult> Login(LoginDto loginDto)
         { 
           var authResponse = await _authManager.Login(loginDto);
             if (authResponse==null)
             {
                 return Unauthorized();
             }
             else
             { 
              return Ok(authResponse);
             }
         }
     }
 }
 */

    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        readonly Repository.IAuthManager _authManager;
        //constructor
        public AccountController(IAuthManager authManager)
        {
            _authManager = authManager;
        }

        [HttpPost]
        [Route("register")]
        public async Task<ActionResult> Register([FromBody] APIUserDto apiUserDto)
        {
            var errors = await _authManager.RegisterUser(apiUserDto);
            if (errors.Any())
            {
                foreach (var error in errors)
                {
                    ModelState.AddModelError(error.Code, error.Description);
                }
                return BadRequest();
            }
            return Ok();

        }
        [HttpPost]
        public async Task<ActionResult> Login([FromBody] LoginDto logindto)
        {
            var authResponse = await _authManager.Login(logindto);
            if (authResponse == null)
            {
                return Unauthorized();
            }
            else
            {
                return Ok(authResponse);
            }
        }
    }
}
