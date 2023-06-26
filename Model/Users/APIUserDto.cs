using System.ComponentModel.DataAnnotations;

namespace Session5.Model.Users
{
    public class APIUserDto
    {
        public string FirstName { get; set; }    
        public string LastName { get; set; }

        [EmailAddress]
        public string Email { get; set; }

        public string Password { get; set; }


    }
}
