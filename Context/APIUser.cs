using Microsoft.AspNetCore.Identity;

namespace Session5.Context
{
    public class APIUser:IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }

    }
}
