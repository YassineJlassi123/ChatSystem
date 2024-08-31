using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProtectedController : ControllerBase
{
    // Endpoint for admin users only
    [HttpGet("admin")]
    [Authorize(Policy = "AdminOnly")]
    public IActionResult GetAdminData()
    {
        return Ok(new { Message = "This is an admin-only endpoint." });
    }

    // Endpoint for regular users only
    [HttpGet("user")]
    [Authorize(Policy = "UserOnly")]
    public IActionResult GetUserData()
    {
        return Ok(new { Message = "This is a user-only endpoint." });
    }

    // Endpoint accessible by any authenticated user
    [HttpGet("any")]
    [Authorize]
    public IActionResult GetAnyData()
    {
        return Ok(new { Message = "This is accessible by any authenticated user." });
    }
}
