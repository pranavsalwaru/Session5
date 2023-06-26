namespace Session5.Model.Users
{
    public class AuthresponseDto
    {
        public string UserId { get; set; }

        public string Token { get; set; }
        public string RefreshToken { get; set; }

        // public string RefreshfToken { get; set; }
        // public string RefreshToken { get; internal set; }
    }
}
