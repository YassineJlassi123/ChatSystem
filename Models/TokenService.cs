using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public class TokenService
{
    private readonly string _jwtKey;
    private readonly string _jwtIssuer;
    private readonly string _jwtAudience;

    public TokenService()
    {
        // Fetch values from environment variables
        _jwtKey = Environment.GetEnvironmentVariable("JwtKey") ?? throw new InvalidOperationException("JWT Key not configured.");
        _jwtIssuer = Environment.GetEnvironmentVariable("JwtIssuer") ?? throw new InvalidOperationException("JWT Issuer not configured.");
        _jwtAudience = Environment.GetEnvironmentVariable("JwtAudience") ?? throw new InvalidOperationException("JWT Audience not configured.");
    }

    public string GenerateToken(string username, string role)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Role, role)
        };

        var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            _jwtIssuer,
            _jwtAudience,
            claims,
            expires: DateTime.Now.AddHours(1),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
