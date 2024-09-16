using Microsoft.AspNetCore.SignalR;
using System.Security.Claims;

public class CustomUserIdProvider : IUserIdProvider
{
    public string GetUserId(HubConnectionContext connection)
    {
        // Assuming you use ClaimsIdentity for user identification
        var userIdClaim = connection.User.FindFirst(ClaimTypes.NameIdentifier);
        return userIdClaim?.Value ?? connection.User.FindFirst(ClaimTypes.Name)?.Value;
    }
}
