using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly TokenService _tokenService;

    public AuthController(ApplicationDbContext context, TokenService tokenService)
    {
        _context = context;
        _tokenService = tokenService;
    }

    // Endpoint for user registration
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegistrationDto request)
    {
        // Validate input
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { Message = "Username and password are required" });
        }

        // Check if the username already exists
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
        {
            return BadRequest(new { Message = "Username already exists" });
        }

        // Hash the password
        var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

        // Save the new user to the database
        var user = new User
        {
            Username = request.Username,
            PasswordHash = passwordHash,
            Role = "User" // Default role
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok(new { Message = "User registered successfully" });
    }

    // Endpoint for user login
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto request)
    {
        // Validate input
        if (string.IsNullOrEmpty(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { Message = "Username and password are required" });
        }

        // Find the user by username
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == request.Username);

        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            return Unauthorized(new { Message = "Invalid username or password" });
        }

        // Generate JWT token
        var token = _tokenService.GenerateToken(user.Username, user.Role);

        return Ok(new TokenDto { Token = token });
    }
}
