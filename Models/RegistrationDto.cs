public class RegistrationDto
{
    public string Username { get; set; }
    public string Password { get; set; } // Plain password, to be hashed before saving
}
