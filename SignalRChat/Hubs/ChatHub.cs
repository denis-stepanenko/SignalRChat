using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;

namespace SignalRChat.Hubs
{
    [Authorize]
    public class ChatHub : Hub
    {
        public async Task Send(string message)
        {
            var userName = Context.User?.Identity?.Name;

            await Clients.All.SendAsync("messageReceived", DateTime.Now.ToString("HH:mm:ss"), userName, message);
        }

        public async Task Type()
        {
            var userName = Context.User?.Identity?.Name;

            await Clients.Others.SendAsync("type", userName);
        }

        public override async Task OnConnectedAsync()
        {
            var userName = Context.User?.Identity?.Name;

            await Clients.All.SendAsync("action", userName + " connected");

            await base.OnConnectedAsync();
        }

        public override async Task OnDisconnectedAsync(Exception? exception)
        {
            var userName = Context.User?.Identity?.Name;

            await Clients.All.SendAsync("action", userName + " disconnected");

            await base.OnDisconnectedAsync(exception);
        }
    }
}
