using Session5.Context.Configurations;
using Session5.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Session5.Context
{
    public class ApplicationDbContext:IdentityDbContext<APIUser>
    {
        //constructor
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> Context) : base(Context)
        {

            
        }
      
    }

  
}
