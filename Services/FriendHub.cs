using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;
using System.Threading.Tasks;

public class FriendHub : Hub
{
    public override Task OnConnectedAsync()
    {
        var userIdentifier = Context.UserIdentifier;
        Console.WriteLine($"User connected: {userIdentifier}");
        return base.OnConnectedAsync();
    }
    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var userIdentifier = Context.UserIdentifier;
        Console.WriteLine($"User disconnected: {userIdentifier}");
        // Handle any additional cleanup if needed

        await base.OnDisconnectedAsync(exception);
    }
    public string GetUserIdentifier()
    {
        return Context.UserIdentifier;
    }
   
}
