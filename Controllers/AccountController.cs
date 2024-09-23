using jwtlogin.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.SignalR;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;
using Microsoft.AspNetCore.Authorization;
using System.Reflection;
using static jwtlogin.Controllers.AccountController;
using Microsoft.AspNetCore.Http.HttpResults;
using CloudinaryDotNet;
using CloudinaryDotNet.Actions;
using System.Security.Policy;
using System.Globalization;

namespace jwtlogin.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> _logger;
        private readonly ApplicationDbContext _context;
        private readonly TokenService _tokenService;
        private readonly IHubContext<FriendHub> _hubContext;
        private readonly Cloudinary _cloudinary;
        private readonly CohereService _cohereService;

        public AccountController(CohereService cohereService, Cloudinary cloudinary, ILogger<AccountController> logger, IHubContext<FriendHub> hubContext, ApplicationDbContext context, TokenService tokenService)
        {
            _cohereService = cohereService;
            _cloudinary = cloudinary;
            _logger = logger;
            _context = context;
            _tokenService = tokenService;
            _hubContext = hubContext;
        }

        // Display registration form
        [HttpGet]
        public IActionResult Register()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("login", "account");
            }
            return View();
        }

        // Handle registration form submission
        [HttpPost]
        public async Task<IActionResult> Register(RegistrationDto model)
        {
            if (!ModelState.IsValid)
            {
                return Json(new { success = false, message = "Invalid input" });
            }

            if (await _context.Users.AnyAsync(u => u.Username == model.Username.ToLower()))
            {
                return Json(new { success = false, message = "Username already exists" });
            }

            var passwordHash = BCrypt.Net.BCrypt.HashPassword(model.Password);
            var user = new User
            {
                Username = model.Username,
                PasswordHash = passwordHash,
                Role = "User"
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Json(new { success = true, message = "Registration successful!" });
        }

        // Display login form
        [HttpGet]
        public IActionResult Login()
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("accueil", "account");
            }
            return View();
        }

        // Handle login form submission
        [HttpPost]
        public async Task<IActionResult> Login(LoginDto model)
        {
            if (!ModelState.IsValid)
            {
                return Json(new { success = false, message = "Invalid input" });
            }

            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == model.Username);
            if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                return Json(new { success = false, message = "Invalid username or password" });
            }
            user.IsOnline = true;
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            var token = _tokenService.GenerateToken(user.Username, user.Role);
            Response.Cookies.Append("jwtToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Set to true if using HTTPS
                SameSite = SameSiteMode.Strict
            });
            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, user.Username),
                    new Claim(ClaimTypes.Role, user.Role)
                }, CookieAuthenticationDefaults.AuthenticationScheme)));

            return Json(new { success = true, message = "Login successful!" });
        }

        // Handle logout
        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            var username = User.Identity?.Name;
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);
            if (user != null)
            {
                user.IsOnline = false;
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
            }
            Response.Cookies.Delete("jwtToken");
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login", "Account");
        }

        [HttpGet]
        public IActionResult GoogleLogin()
        {
            var properties = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(GoogleLoginCallback))
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet]
        public async Task<IActionResult> GoogleLoginCallback()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (!authenticateResult.Succeeded)
                return RedirectToAction(nameof(Login));

            var claimsPrincipal = authenticateResult.Principal;
            var googleId = claimsPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = claimsPrincipal.FindFirstValue(ClaimTypes.Name);

            var user = await _context.Users.SingleOrDefaultAsync(u => u.GoogleId == googleId);

            if (user == null)
            {
                user = new User
                {
                    Username = username,
                    GoogleId = googleId,
                    Role = "User"
                    // No PasswordHash needed
                };

                _context.Users.Add(user);
                await _context.SaveChangesAsync();
            }

            var token = _tokenService.GenerateToken(user.Username, user.Role);
            Response.Cookies.Append("jwtToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Set to true if using HTTPS
                SameSite = SameSiteMode.Strict
            });

            return RedirectToAction("accueil", "account");
        }

        // GET: FriendRequests
        [HttpGet]
        public async Task<IActionResult> GetFriendRequests(int page = 1, int pageSize = 7)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var user = await _context.Users
                .Include(u => u.FriendRequestsReceived)
                .ThenInclude(fr => fr.Sender)
                .SingleOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                return NotFound();
            }

            // Calculate total friend requests count for pagination
            var totalRequests = user.FriendRequestsReceived.Count;
            var hasMoreRequests = totalRequests > page * pageSize;

            var friendRequests = user.FriendRequestsReceived
                .OrderByDescending(fr => fr.RequestedAt) // Ensure the most recent requests are fetched first
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(fr => new FriendRequestViewModel
                {
                    Id = fr.Id,
                    SenderUsername = fr.Sender.Username,
                    RequestedAt = fr.RequestedAt,
                    ProfilImage=fr.Sender.ProfileImageUrl
                }).ToList();

          

            return Ok(new
            {
                FriendRequests = friendRequests,
                HasMoreRequests = hasMoreRequests
            });
        }

        // POST: AcceptFriendRequest

        [HttpPost]
        public async Task<IActionResult> AcceptFriendRequest([FromBody] int requestId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var user = await _context.Users
                .Include(u => u.FriendRequestsReceived)
                .SingleOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                return Json(new { success = false, message = "User not found" });
            }

            var request = user.FriendRequestsReceived
                .SingleOrDefault(fr => fr.Id == requestId);
            var recieverFreind = await _context.Users.SingleOrDefaultAsync(u => u.Id == request.SenderId);
            if (request == null)
            {
                return Json(new { success = false, message = "Friend request not found" });
            }


            user.NumberOfFriends += 1;
            recieverFreind.NumberOfFriends += 1;




            var friend = await _context.Users.SingleOrDefaultAsync(u => u.Id == request.SenderId);
            if (friend != null)
            {
                _context.UserFriends.Add(new UserFriend
                {
                    UserId = user.Id,
                    FriendId = friend.Id
                });
                _context.UserFriends.Add(new UserFriend
                {
                    UserId = friend.Id,
                    FriendId = user.Id
                });
            }
            else
            {
                return Json(new { success = false, message = "Sender not found" });
            }
            var notification = new Notification
            {
                Message = $"{user.Username} accepted your friend request.",
                UserId = recieverFreind.Id,
                TriggeredByUserId = user.Id
            };
            _context.Notifications.Add(notification);
            await _context.SaveChangesAsync();

            // Send SignalR notification
            var receiverUserId = recieverFreind.GoogleId ?? recieverFreind.Username;
            await _hubContext.Clients.User(receiverUserId).SendAsync("ReceiveNotification", new
            {
                Id = notification.Id,
                Message = notification.Message,
                TriggeredByUser = new
                {
                    Username = user.Username,
                    ProfileImageUrl = user.ProfileImageUrl // Ensure this exists
                },
                CreatedAt = notification.CreatedAt
            });

            _context.FriendRequests.Remove(request);
            await _context.SaveChangesAsync();

            return Json(new { success = true, message = "Friend request accepted!" });
        }


        // POST: DeclineFriendRequest

        [HttpPost]
        public async Task<IActionResult> DeclineFriendRequest([FromBody] int requestId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var user = await _context.Users
                .Include(u => u.FriendRequestsReceived)
                .ThenInclude(u => u.Sender)
                .SingleOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                return Json(new { success = false, message = "User not found" });
            }
         
            var request = user.FriendRequestsReceived

                .SingleOrDefault(fr => fr.Id == requestId);


            if (request == null)
            {
                return Json(new { success = false, message = "Friend request not found" });
            }
            var notification = new Notification
            {
                Message = $"{user.Username} Declined your friend request.",
                UserId = request.Sender.Id,
                TriggeredByUserId = user.Id
            };
            _context.Notifications.Add(notification);
            await _context.SaveChangesAsync();

            // Send SignalR notification
            var receiverUserId = request.Sender.GoogleId ?? request.Sender.Username;
            await _hubContext.Clients.User(receiverUserId).SendAsync("ReceiveNotification", new
            {
                Id = notification.Id,
                Message = notification.Message,
                TriggeredByUser = new
                {
                    Username = user.Username,
                    ProfileImageUrl = user.ProfileImageUrl // Ensure this exists
                },
                CreatedAt = notification.CreatedAt
            });
            _context.FriendRequests.Remove(request);
            await _context.SaveChangesAsync();

            return Json(new { success = true, message = "Friend request Declined" });
        }

        [HttpDelete]
        public async Task<IActionResult> DeleteFriendRequest(int requestId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Unauthorized();
            }
          
            var currentUser = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
          
            var friendRequest = await _context.FriendRequests.SingleOrDefaultAsync(fr => fr.Id == requestId && fr.SenderId == currentUser.Id);

            if (friendRequest == null)
            {
                return Json(new { success = false, message = "Friend request not found or you are not authorized to cancel it." });
            }

            _context.FriendRequests.Remove(friendRequest);
            await _context.SaveChangesAsync();

            return Json(new { success = true, message = "Friend request canceled." });
        }


        [HttpPost]
        public async Task<IActionResult> SendFriendRequest([FromBody] string username)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var sender = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
            var receiver = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

            if (sender == null || receiver == null)
            {
                return Json(new { success = false, message = "User not found" });
            }

            if (sender.Username == receiver.Username)
            {
                return Json(new { success = false, message = "You cannot send a friend request to yourself." });
            }

            var alreadyFriends = await _context.UserFriends
                .AnyAsync(f => (f.UserId == sender.Id && f.FriendId == receiver.Id) || (f.UserId == receiver.Id && f.FriendId == sender.Id));

            if (alreadyFriends)
            {
                return Json(new { success = false, message = "You are already friends with this user." });
            }

            var existingRequest = await _context.FriendRequests
                .AnyAsync(fr => fr.SenderId == sender.Id && fr.ReceiverId == receiver.Id);

            if (existingRequest)
            {
                return Json(new { success = false, message = "Friend request already exists." });
            }

            var friendRequest = new FriendRequest
            {
                SenderId = sender.Id,
                ReceiverId = receiver.Id,
                RequestedAt = DateTime.UtcNow,
                IsAccepted = false
            };
            _context.FriendRequests.Add(friendRequest);

            // Create notification
            var notification = new Notification
            {
                Message = $"{sender.Username} sent you a friend request.",
                UserId = receiver.Id,
                TriggeredByUserId = sender.Id
            };
            _context.Notifications.Add(notification);
            await _context.SaveChangesAsync();

            // Send SignalR notification
            var receiverUserId = receiver.GoogleId ?? receiver.Username;
            await _hubContext.Clients.User(receiverUserId).SendAsync("ReceiveFriendRequest", new FriendRequestViewModel
            {
                Id = friendRequest.Id,
                SenderUsername = sender.Username,
                RequestedAt = friendRequest.RequestedAt,
                ProfilImage=sender.ProfileImageUrl
            });

            return Json(new { success = true, message = "Friend request sent!" });
        }



        [HttpGet]
        public async Task<IActionResult> SearchFriends(string query)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var username = User.Identity.Name;
            var currentUser = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);
            var friends = await _context.UserFriends
       .Where(f => f.UserId == currentUser.Id || f.FriendId == currentUser.Id)
       .Select(f => f.UserId == currentUser.Id ? f.FriendId : f.UserId)
       .ToListAsync();
            var friendRequests = await _context.FriendRequests
        .Where(fr => fr.Sender.Username == username || fr.Receiver.Username == username)
        .Select(fr => new { fr.SenderId, fr.ReceiverId, fr.Id, fr.IsAccepted })
        .ToListAsync();

            var sentRequests = friendRequests
                .Where(fr => fr.SenderId == currentUser.Id)
                .ToDictionary(fr => fr.ReceiverId, fr => fr.Id);

            var receivedRequests = friendRequests
                .Where(fr => fr.ReceiverId == currentUser.Id)
                .ToDictionary(fr => fr.SenderId, fr => fr.Id);
            var normalizedQuery = query.ToLower();
            var users = await _context.Users
                .Where(u => u.Username.ToLower().Contains(normalizedQuery) && u.Username != User.Identity.Name)
                .Select(u => new
                {
                    u.Id,
                    u.Username,
                    ProfileImage = u.ProfileImageUrl,
                    IsFriend = friends.Contains(u.Id),
                    SentRequestId = sentRequests.ContainsKey(u.Id) ? sentRequests[u.Id] : (int?)null,
                    ReceivedRequestId = receivedRequests.ContainsKey(u.Id) ? receivedRequests[u.Id] : (int?)null
                })
                .ToListAsync();

            return Ok(users);
        }
        [HttpGet]
        public async Task<IActionResult> Conversations()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var userId = await _context.Users
                .Where(u => u.Username == username)
                .Select(u => u.Id)
                .FirstOrDefaultAsync();

            // Get the user's friends and conversations
            var friends = await _context.UserFriends
                .Where(uf => uf.UserId == userId)
                .Include(uf => uf.User)
                .Include(uf => uf.Friend)
                .ToListAsync();

            var conversations = new List<ConversationViewModel>();

            foreach (var friend in friends)
            {
                var friendId = friend.UserId == userId ? friend.FriendId : friend.UserId;

                // Fetch the conversation between the user and the friend, if it exists
                var existingConversation = await _context.Conversations
                    .Where(c => (c.User1Id == userId && c.User2Id == friendId) || (c.User1Id == friendId && c.User2Id == userId))
                    .Include(c => c.Messages)
                    .ThenInclude(m => m.Sender)  // Include the sender details
                    .Include(c => c.User1)
                    .Include(c => c.User2)
                    .FirstOrDefaultAsync();

                if (existingConversation == null)
                {
                    // If no conversation exists, create a new one
                    var newConversation = new Conversation
                    {
                        User1Id = userId,
                        User2Id = friendId,
                    };
                    _context.Conversations.Add(newConversation);
                    await _context.SaveChangesAsync();

                    existingConversation = newConversation;
                }

                // Get the last message in the conversation
                var lastMessage = existingConversation.Messages
                    .OrderByDescending(m => m.SentAt)
                    .FirstOrDefault();

                // Determine if there are unread messages sent by the friend
                bool hasUnreadMessages = lastMessage != null &&
                                         lastMessage.SenderId != userId &&
                                         !lastMessage.IsRead;

                // Create the view model for the conversation
                conversations.Add(new ConversationViewModel
                {
                    Id = existingConversation.Id,
                    FriendUsername = existingConversation.User1Id == userId
                        ? existingConversation.User2.Username
                        : existingConversation.User1.Username,
                    LastMessageContent = lastMessage?.Content,
                    LastMessageSentAt = lastMessage?.SentAt ?? DateTime.MinValue,
                    HasUnreadMessages = hasUnreadMessages,  // Flag to indicate unread messages
                    ImageProfile = friend.Friend.ProfileImageUrl
                });
            }

            // Order the conversations by the timestamp of the last message
            conversations = conversations
                .OrderByDescending(c => c.LastMessageSentAt)
                .ToList();

            // If a search term is provided, filter the conversations
           

            

            return View(conversations);
        }
        [HttpGet]
        public async Task<IActionResult> SearchConversations(string searchTerm)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var userId = await _context.Users
                .Where(u => u.Username == username)
                .Select(u => u.Id)
                .FirstOrDefaultAsync();
            var normalizedQuery = searchTerm?.ToLower() ?? string.Empty;

            var conversations = await _context.Conversations
                .Where(c => (c.User1Id == userId || c.User2Id == userId)  && (c.User1Id == userId ? c.User2.Username.ToLower().Contains(normalizedQuery) : c.User1.Username.ToLower().Contains(normalizedQuery)))

                .Select(c => new
                {
                    Id = c.Id,
                    FriendUsername = c.User1Id == userId ? c.User2.Username : c.User1.Username, // Adjust based on which user is the friend
                    ImageProfile = c.User1Id == userId ? c.User2.ProfileImageUrl : c.User1.ProfileImageUrl, // Adjust based on which user is the friend
                    LastMessageContent = c.Messages.OrderByDescending(m => m.SentAt).Select(m => m.Content).FirstOrDefault(),
                    LastMessageSentAt = c.Messages.OrderByDescending(m => m.SentAt).Select(m => m.SentAt).FirstOrDefault(),
                    HasUnreadMessages = c.Messages.Any(m => m.SenderId != userId && !m.IsRead)
                })
                .OrderByDescending(c => c.LastMessageSentAt)
                .ToListAsync();

            return Json(conversations);
        }

        [HttpGet]
        public async Task<IActionResult> ConversationDetail(int id)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var userId = await _context.Users
                .Where(u => u.Username == username)
                .Select(u => u.Id)
                .FirstOrDefaultAsync();

            var conversation = await _context.Conversations
                .Where(c => (c.User1Id == userId || c.User2Id == userId) && c.Id == id)
                .Include(c => c.Messages)
                .Include(c => c.User1)
                .Include(c => c.User2)
                .Select(c => new ConversationDetailViewModel
                {
                    ConversationId = id,
                    FriendUsername = c.User1Id == userId ? c.User2.Username : c.User1.Username,
                    Messages = c.Messages
                        .OrderBy(m => m.SentAt)
                        .Select(m => new MessageViewModel
                        {
                            Content = m.Content,
                            SentAt = m.SentAt,
                            SenderUsername = m.Sender.Username
                        })
                        .ToList(),
                    ImageProfileFr = c.User1Id == userId ? c.User2.ProfileImageUrl : c.User1.ProfileImageUrl
                })
                .FirstOrDefaultAsync();

            if (conversation == null)
            {
                return NotFound();
            }

            // Check if the request was made by JS fetch for desktop (AJAX request)
            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return PartialView("_ConversationDetailPartial", conversation); // Create this partial for desktop
            }

            // Otherwise, return the full view for mobile devices
            return View("ConversationDetailMobile", conversation);
        }


        [HttpPost]
        public async Task<IActionResult> SendMessage([FromBody] SendMessageRequest request)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var sender = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
            var recipient = await _context.Users.SingleOrDefaultAsync(u => u.Username == request.RecipientUsername);

            if (sender == null || recipient == null)
            {
                return Json(new { success = false, message = "User not found" });
            }

            var conversation = await _context.Conversations
                .Where(c => (c.User1Id == sender.Id && c.User2Id == recipient.Id) || (c.User1Id == recipient.Id && c.User2Id == sender.Id))
                .FirstOrDefaultAsync();

            if (conversation == null)
            {
                conversation = new Conversation { User1Id = sender.Id, User2Id = recipient.Id };
                _context.Conversations.Add(conversation);
                await _context.SaveChangesAsync();
            }

            var message = new Message
            {
                ConversationId = conversation.Id,
                SenderId = sender.Id,
                Content = request.Content,
                SentAt = DateTime.UtcNow
            };
            _context.Messages.Add(message);

            // Create notification
           
            await _context.SaveChangesAsync();

            // Send SignalR notification
            var recipientUserId = recipient.GoogleId ?? recipient.Username;
            await _hubContext.Clients.User(recipientUserId).SendAsync("ReceiveMessage", new MessageViewModel
            {
                Content = message.Content,
                SentAt = message.SentAt,
                SenderUsername = sender.Username
            });

            return Json(new { success = true, message = "Message sent!" });
        }

        [HttpPost]
        public async Task<IActionResult> MarkAllMessagesAsRead(int conversationId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var username = User.Identity.Name;
            var userId = await _context.Users
                .Where(u => u.Username == username)
                .Select(u => u.Id)
                .FirstOrDefaultAsync();

            var conversation = await _context.Conversations
                .Include(c => c.Messages)
                .FirstOrDefaultAsync(c => c.Id == conversationId);

            if (conversation == null)
            {
                return NotFound();
            }

            var messages = conversation.Messages
                .Where(m => m.SenderId != userId && !m.IsRead);

            foreach (var message in messages)
            {
                message.IsRead = true;
            }

            await _context.SaveChangesAsync();

            return Ok();
        }


        [HttpPost]
        public async Task<IActionResult> UploadProfileImage(IFormFile profileImage)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            if (profileImage != null && profileImage.Length > 0 && profileImage.ContentType.StartsWith("image/"))
            {
                var username = User.Identity.Name;
                var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

                if (user == null)
                {
                    TempData["ErrorMessage"] = "User not found.";
                    return RedirectToAction("Profile");
                }

               

                    // Upload the new profile image to Cloudinary
                    var uploadParams = new ImageUploadParams
                    {
                        File = new FileDescription(profileImage.FileName, profileImage.OpenReadStream()),
                        Folder = "profiles",
                        Transformation = new Transformation().Crop("fill").Gravity("face").Width(500).Height(500)
                    };

                    var uploadResult = await _cloudinary.UploadAsync(uploadParams);

                    if (uploadResult.StatusCode == System.Net.HttpStatusCode.OK)
                    {
                        // Update the user's profile image URL
                        user.ProfileImageUrl = uploadResult.SecureUrl.ToString();
                        _context.Update(user);
                        await _context.SaveChangesAsync();

                        TempData["SuccessMessage"] = "Profile image updated successfully!";
                        return RedirectToAction("Profile", new { username = user.Username });
                    }
                    else
                    {
                        TempData["ErrorMessage"] = "Error uploading new profile image.";
                        return RedirectToAction("Profile");
                    }
              
            }
            else
            {
                TempData["ErrorMessage"] = "Invalid file. Please upload a valid image.";
                return RedirectToAction("Profile");
            }
        }

      




        [HttpGet]
        public async Task<IActionResult> Profile(string username)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var user = await _context.Users
                .Include(u => u.Friends) // Include the Friends collection
                .ThenInclude(uf => uf.Friend) // Include the Friend object in UserFriend
                .Include(u => u.Posts) // Include thFe Posts collection
                .ThenInclude(p => p.Comments)
                .ThenInclude(p => p.User)// Include Comments within Posts
                .Include(u => u.Posts) // Include Posts again to access Interactions
                .ThenInclude(p => p.Interactions) // Include Interactions within Posts
                .SingleOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());

            if (user == null)
            {
                return NotFound();
            }
            var loggedInUsername = User.Identity.Name;

            // Check if the logged-in user is the same as the profile user
            var isProfileOwner = loggedInUsername == user.Username;
            var initialPosts = user.Posts
                .OrderByDescending(p => p.CreatedAt)
                .Take(10)
                .Select(p => new PostViewModel
                {
                    Id = p.Id, // Make sure to include Id for lazy loading
                    Content = p.Content,
                    ImageUrl = p.ImageUrl,
                    CreatedAt = p.CreatedAt,
                    Username = user.Username, // Assuming posts are linked to the same user
                    JaimeCount = p.JaimeCount,
                    JadoreCount = p.JadoreCount,
                    CommentCount = p.CommentCount,
                    HologramText=p.HologramText,
                    Latitude=p.Latitude,
                    Longitude=p.Longitude,
                    Comments = p.Comments.Select(c => new CommentDto
                    {
                        Id = c.Id,
                        Content = c.Content,
                        CreatedAt = c.CreatedAt,
                        Username = c.User.Username,
                        ProfileImageUrl = c.User.ProfileImageUrl
                    }
                    ).ToList() // Fetch and map comments here
                }).ToList();

            var viewModel = new ProfileAndPostViewModel
            {
                User = new UserViewModel
                {
                    Username = user.Username,
                    ProfileImageUrl = user.ProfileImageUrl,
                    CoverImageUrl = user.CoverImageUrl,
                    Friends = user.Friends.Select(f => new FriendModel
                    {
                        Username = f.Friend.Username,
                        ProfileImageUrl = f.Friend.ProfileImageUrl,
                    }).ToList(),
                    NumberOfFriends = user.NumberOfFriends
                },
                Post = new CreatePostViewModel(), // Initialize with default values if needed
                Posts = initialPosts,
                TotalPosts = user.Posts.Count,// Total number of posts
                IsProfileOwner= isProfileOwner
            };

            return View(viewModel);
        }


        [HttpGet]
        public async Task<IActionResult> LoadProfilePosts(int pageNumber, int pageSize , string username)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var user = await _context.Users
                .Include(u => u.Posts)
                .ThenInclude(p => p.Comments)
                .ThenInclude(p => p.User)// Include Comments within Posts
                .Include(u => u.Posts) // Include Posts again to access Interactions
                .ThenInclude(p => p.Interactions) // Include Interactions within Posts
                .SingleOrDefaultAsync(u => u.Username == username);

            if (user == null)
            {
                return NotFound();
            }

            var posts = user.Posts
                .OrderByDescending(p => p.CreatedAt)
                .Skip((pageNumber - 1) * pageSize)
                .Take(pageSize)
                .Select(p => new PostViewModel
                {
                    Id = p.Id,
                    Content = p.Content,
                    ImageUrl = p.ImageUrl,
                    CreatedAt = p.CreatedAt,
                    Username = user.Username,
                    JaimeCount = p.JaimeCount,
                    JadoreCount = p.JadoreCount,
                    CommentCount = p.CommentCount,
                    HologramText = p.HologramText,
                    Latitude = p.Latitude,
                    Longitude = p.Longitude,
                    Comments = p.Comments.Select(c => new CommentDto
                    {
                        Id = c.Id,
                        Content = c.Content,
                        CreatedAt = c.CreatedAt,
                        Username = c.User.Username,
                        ProfileImageUrl = c.User.ProfileImageUrl
                    }).ToList() // Fetch and map comments here
                }).ToList();
            
            return Json(new { posts = posts });
        }


        [HttpPost]
        public async Task<IActionResult> UploadCoverImage(IFormFile coverImage)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            if (coverImage != null && coverImage.Length > 0 && coverImage.ContentType.StartsWith("image/"))
            {
                var username = User.Identity.Name;
                var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

                if (user == null)
                {
                    TempData["ErrorMessage"] = "User not found.";
                    return RedirectToAction("Profile");
                }
               

                // Upload the new cover image to Cloudinary
                var uploadParams = new ImageUploadParams
                {
                    File = new FileDescription(coverImage.FileName, coverImage.OpenReadStream()),
                    Folder = "covers",
                    Transformation = new Transformation().Crop("fill").Gravity("face").Width(1500).Height(500)
                };

                var uploadResult = await _cloudinary.UploadAsync(uploadParams);

                if (uploadResult.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    // Update the user's cover image URL
                    user.CoverImageUrl = uploadResult.SecureUrl.ToString();
                    _context.Update(user);
                    await _context.SaveChangesAsync();

                    TempData["SuccessMessage"] = "Cover image updated successfully!";
                    return RedirectToAction("Profile", new { username = user.Username });
                }
                else
                {
                    TempData["ErrorMessage"] = "Error uploading new cover image.";
                    return RedirectToAction("Profile");
                }
            }
            else
            {
                TempData["ErrorMessage"] = "Invalid file. Please upload a valid image.";
                return RedirectToAction("Profile");
            }
        }



        [HttpPost]
        public async Task<IActionResult> CreatePost(ProfileAndPostViewModel model)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            // For nested models, like Post, do the same
            double? latitude = null;
            double? longitude = null;

            if (!string.IsNullOrEmpty(model.Post.Latitude) &&
                double.TryParse(model.Post.Latitude, NumberStyles.Any, CultureInfo.InvariantCulture, out double parsedLatitude))
            {
                latitude = parsedLatitude;
            }

            if (!string.IsNullOrEmpty(model.Post.Longitude) &&
                double.TryParse(model.Post.Longitude, NumberStyles.Any, CultureInfo.InvariantCulture, out double parsedLongitude))
            {
                longitude = parsedLongitude;
            }

            var postType = model.Post.Type;

            // Validate content based on post type
            if (postType == "text_image")
            {
                if (string.IsNullOrWhiteSpace(model.Post.Content) &&
                    (model.Post.Image == null || model.Post.Image.Length == 0 || !model.Post.Image.ContentType.StartsWith("image/")))
                {
                    return Json(new
                    {
                        success = false,
                        message = "Please provide either content or a valid image."
                    });
                }
            }
            else if (postType == "ai_image")
            {
                // Ensure that an image prompt is provided
                if (string.IsNullOrWhiteSpace(model.Post.ImagePrompt))
                {
                    return Json(new
                    {
                        success = false,
                        message = "Please provide an image prompt."
                    });
                }
            }
           

            // Only try to parse latitude and longitude if the post type is "hologram"
           else if (model.Post.Type == "hologram")
            {
                if (string.IsNullOrEmpty(model.Post.Latitude) ||
                    string.IsNullOrEmpty(model.Post.Longitude)) { 
                    // Return error message if not provided for hologram type
                    return Json(new
                    {
                        success = false,
                        message = "Please provide valid latitude and longitude for hologram posts."
                    });
                }
            }

            // Handle image upload if provided for text_image
            string imageUrl = null;
            if (postType == "text_image" && model.Post.Image != null && model.Post.Image.Length > 0 && model.Post.Image.ContentType.StartsWith("image/"))
            {
                var uploadParams = new ImageUploadParams
                {
                    File = new FileDescription(model.Post.Image.FileName, model.Post.Image.OpenReadStream()),
                    Folder = "posts",
                    Transformation = new Transformation().Crop("fill").Gravity("face").Width(800).Height(600)
                };

                var uploadResult = await _cloudinary.UploadAsync(uploadParams);

                if (uploadResult.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    imageUrl = uploadResult.SecureUrl.ToString();
                }
                else
                {
                    return Json(new
                    {
                        success = false,
                        message = "Error uploading image."
                    });
                }
            }

            // Handle image generation if a prompt is provided
            if (postType == "ai_image" && !string.IsNullOrWhiteSpace(model.Post.ImagePrompt))
            {
                // URL-encode the prompt
                var encodedPrompt = Uri.EscapeDataString(model.Post.ImagePrompt);
                var url = $"https://image.pollinations.ai/prompt/{encodedPrompt}?model=flux-realism&width=800&height=600&nologo=true";

                using (var httpClient = new HttpClient())
                {
                    var response = await httpClient.GetAsync(url);
                    if (response.IsSuccessStatusCode)
                    {
                        var imageBytes = await response.Content.ReadAsByteArrayAsync();

                        var uploadParams = new ImageUploadParams
                        {
                            File = new FileDescription("generated-image.jpg", new MemoryStream(imageBytes)),
                            Folder = "posts",
                            Transformation = new Transformation().Crop("fill").Gravity("face").Width(800).Height(600)
                        };

                        var uploadResult = await _cloudinary.UploadAsync(uploadParams);

                        if (uploadResult.StatusCode == System.Net.HttpStatusCode.OK)
                        {
                            imageUrl = uploadResult.SecureUrl.ToString();
                        }
                        else
                        {
                            return Json(new
                            {
                                success = false,
                                message = "Error uploading generated image."
                            });
                        }
                    }
                    else
                    {
                        return Json(new
                        {
                            success = false,
                            message = "Error generating image."
                        });
                    }
                }
            }

            var currentUser = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
           
            var post = new Post
            {
                Content = model.Post.Content, // Can be null or empty
                ImageUrl = imageUrl, // Can be null if no image is provided
                UserId = currentUser.Id,
                CreatedAt = DateTime.UtcNow,
                HologramText=model.Post.HologramText,
                Latitude= latitude,
                Longitude= longitude,

            };

            _context.Posts.Add(post);
            await _context.SaveChangesAsync();

            // Return JSON response with post details
            return Json(new
            {
                success = true,
                post = new
                {
                    Id = post.Id,
                    Content = post.Content,
                    CreatedAt = post.CreatedAt,
                    ProfileImageUrl = currentUser.ProfileImageUrl,
                    Username = currentUser.Username,
                    ImageUrl = post.ImageUrl,
                    JaimeCount = post.JaimeCount,
                    CommentCount = post.CommentCount
                }
            });
        }


        [HttpPost]
        public async Task<IActionResult> Command([FromBody] VoiceCommandRequest request)
        {
            // Ensure the request contains text and a list of commands
            if (request == null || string.IsNullOrWhiteSpace(request.Text) || request.Commands == null || request.Commands.Length == 0)
            {
                return BadRequest("Invalid request. Ensure both text input and commands are provided.");
            }

            // Prepare the prompt with the exact text you requested
            var prompt = $@"
I want you to analyze a user input that may contain errors, extra words, or incorrect syntax, and match it to a list of predefined commands. After identifying the closest command, you need to extract the relevant variables (like username or content) from the input and return the matched command with the correct structure.

Here is a list of possible commands:

{string.Join("\n", request.Commands)}

For example, if the input is: i want to send a message whats up today to morta, you should recognize it matches the send message (content) to (username) command and return: send message whats up today to morta.

Important notes:
- You should ignore garbage words or errors in syntax.
- Always return the command in its exact structure with extracted variables.
- If no command matches the input, respond with no.
- Do not add or modify anything outside the provided structure.

User Input: '{request.Text}'";

            // Get completion from Cohere or any AI model service you are using
            var response = await _cohereService.GetChatResponseAsync(prompt);

            // Return the response directly
            return Ok(new { command = response.Trim() });
        }
    

    // VoiceCommandRequest class definition
    public class VoiceCommandRequest
    {
        public string Text { get; set; } // User's input string
        public string[] Commands { get; set; } // List of possible commands
    }

    public async Task<IActionResult> Accueil()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var currentUser = await _context.Users
                .Include(u => u.Friends) // Assuming you have a Friends collection
                .SingleOrDefaultAsync(u => u.Username == User.Identity.Name);

            if (currentUser == null)
            {
                return NotFound(); // Or handle user not found case
            }

            var friendIds = currentUser.Friends.Select(f => f.FriendId).ToList();
            var friendCount = friendIds.Count;
            var currentUserId = currentUser.Id;

            IQueryable<Post> postQuery;

            if (friendCount < 20)
            {
                // Fetch posts from all users, excluding current user's posts
                postQuery = _context.Posts
                    .Where(p => p.UserId != currentUserId) // Exclude current user's posts
                    .Include(p => p.User) // To show user's info
                    .Include(p => p.Comments) // To show comments
                    .ThenInclude(c => c.User) // To show comment user's info
                    .Include(p => p.Interactions) // To show likes/jadore count
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(10); // Fetch initial set of posts
            }
            else
            {
                // Fetch posts from friends only, excluding current user's posts
                postQuery = _context.Posts
                    .Where(p => friendIds.Contains(p.UserId) && p.UserId != currentUserId) // Exclude current user's posts
                    .Include(p => p.User) // To show user's info
                    .Include(p => p.Comments) // To show comments
                    .ThenInclude(c => c.User) // To show comment user's info
                    .Include(p => p.Interactions) // To show likes/jadore count
                    .OrderByDescending(p => p.CreatedAt)
                    .Take(10); // Fetch initial set of posts
            }

            var initialPosts = await postQuery.ToListAsync();

            // Count total posts for pagination
            int totalPosts;

            if (friendCount < 20)
            {
                totalPosts = await _context.Posts
                    .CountAsync(p => p.UserId != currentUserId); // Exclude current user's posts
            }
            else
            {
                totalPosts = await _context.Posts
                    .CountAsync(p => friendIds.Contains(p.UserId) && p.UserId != currentUserId); // Exclude current user's posts
            }

            var viewModel = new AccueilViewModel
            {
                User = currentUser,
                Posts = initialPosts,
                TotalPosts = totalPosts,
                PageNumber = 1,
                PageSize = 10
            };

            return View(viewModel);
        }

        [HttpGet]
        public async Task<IActionResult> LoadMorePosts(int pageNumber, int pageSize)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var currentUser = await _context.Users
                .Include(u => u.Friends) // Assuming you have a Friends collection
                .SingleOrDefaultAsync(u => u.Username == User.Identity.Name);

            if (currentUser == null)
            {
                return NotFound(); // Or handle user not found case
            }

            var friendIds = currentUser.Friends.Select(f => f.FriendId).ToList();
            var friendCount = friendIds.Count;
            var currentUserId = currentUser.Id;

            IQueryable<Post> postQuery;

            if (friendCount < 20)
            {
                // Fetch posts from all users, excluding current user's posts
                postQuery = _context.Posts
                    .Where(p => p.UserId != currentUserId) // Exclude current user's posts
                    .OrderByDescending(p => p.CreatedAt)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize);
            }
            else
            {
                // Fetch posts from friends only, excluding current user's posts
                postQuery = _context.Posts
                    .Where(p => friendIds.Contains(p.UserId) && p.UserId != currentUserId) // Exclude current user's posts
                    .OrderByDescending(p => p.CreatedAt)
                    .Skip((pageNumber - 1) * pageSize)
                    .Take(pageSize);
            }

            var friendPosts = await postQuery
                .Select(p => new PostDto
                {
                    Id = p.Id,
                    Content = p.Content,
                    ImageUrl = p.ImageUrl,
                    CreatedAt = p.CreatedAt,
                    JaimeCount = p.Interactions.Count,
                    CommentCount = p.Comments.Count,
                    User = new UserDto
                    {
                        Username = p.User.Username,
                        ProfileImageUrl = p.User.ProfileImageUrl
                    },
                    Comments = p.Comments.Select(c => new CommentDto
                    {
                        Id = c.Id,
                        Content = c.Content,
                        CreatedAt = c.CreatedAt,
                        Username = c.User.Username,
                        ProfileImageUrl = c.User.ProfileImageUrl
                    }).ToList()
                })
                .ToListAsync();

            int totalPosts;

            if (friendCount < 20)
            {
                totalPosts = await _context.Posts
                    .CountAsync(p => p.UserId != currentUserId); 
            }
            else
            {
                totalPosts = await _context.Posts
                    .CountAsync(p => friendIds.Contains(p.UserId) && p.UserId != currentUserId); 
            }

            var result = new
            {
                posts = friendPosts,
                totalPosts
            };

            return Json(result);
        }


        [HttpPost]
        public async Task<IActionResult> LikePost([FromBody] int postId)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var currentUser = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (currentUser == null)
            {
                return Unauthorized();
            }

            var post = await _context.Posts
                .Include(p => p.User)
                .Include(p => p.Interactions)
                .FirstOrDefaultAsync(p => p.Id == postId);

            if (post == null)
            {
                return NotFound();
            }

            var existingInteraction = post.Interactions.FirstOrDefault(i => i.UserId == currentUser.Id && i.InteractionType == InteractionType.Jaime);
            if (existingInteraction != null)
            {
                _context.PostInteractions.Remove(existingInteraction);
                await _context.SaveChangesAsync();
                return Json(new { JaimeCount = post.JaimeCount });
            }

            var postInteraction = new PostInteraction
            {
                PostId = postId,
                UserId = currentUser.Id,
                InteractionType = InteractionType.Jaime,
                InteractedAt = DateTime.UtcNow
            };
            _context.PostInteractions.Add(postInteraction);
            await _context.SaveChangesAsync();

      
            // Create notification

            var receiverUserId = post.User.GoogleId ?? post.User.Username;
            if (receiverUserId != currentUser.GoogleId && receiverUserId != User.Identity.Name)
            {
                // Send SignalR notification
                var notification = new Notification
                {
                    Message = $"{currentUser.Username} liked your post.",
                    UserId = post.User.Id,
                    TriggeredByUserId = currentUser.Id,
                    PostId = postId
                };
                _context.Notifications.Add(notification);
                await _context.SaveChangesAsync();
                await _hubContext.Clients.User(receiverUserId).SendAsync("ReceiveNotification", new{ Id = notification.Id,
                    Message = notification.Message,
                    PostId = post.Id,
                    TriggeredByUser = new
                    {
                        Username = currentUser.Username,
                        ProfileImageUrl = currentUser.ProfileImageUrl // Ensure this exists
                    },
                    CreatedAt = notification.CreatedAt,
                  
                }) ;
            }
            return Json(new { JaimeCount = post.JaimeCount });
        }

        [HttpGet]
        public async Task<IActionResult> GetUnreadRequestCount()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var currentUser = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
            var count = await _context.FriendRequests
                .Where(r => r.ReceiverId == currentUser.Id && !r.IsRead)
                .CountAsync();

            return Json(new { Count=count });
        }

        [HttpGet]
        public async Task<IActionResult> GetUnreadMessageCount()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            // Get the current authenticated user
            var currentUser = await _context.Users
                .SingleOrDefaultAsync(u => u.Username == User.Identity.Name);

            // Check if the user exists
            if (currentUser == null)
            {
                return NotFound();
            }

            // Get the count of unread messages where the current user is involved in the conversation
            var count = await _context.Messages
                .Where(m =>
                    (m.Conversation.User1Id == currentUser.Id || m.Conversation.User2Id == currentUser.Id)
                    && m.SenderId != currentUser.Id // Ensure messages were sent by the other user
                    && !m.IsRead)
                .CountAsync();

            // Return the unread message count as JSON
            return Json(new { Count = count });
        }


        [HttpPost]
        public async Task<IActionResult> AddComment([FromBody] CommentViewModel commentViewModel)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            if (!ModelState.IsValid)
            {
                return BadRequest("Invalid comment data");
            }

            var currentUser = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
            if (currentUser == null)
            {
                return Unauthorized();
            }

            var post = await _context.Posts.Include(p => p.Comments).Include(p => p.User).FirstOrDefaultAsync(p => p.Id == commentViewModel.PostId);
            if (post == null)
            {
                return NotFound();
            }

            var comment = new PostComment
            {
                Content = commentViewModel.Content,
                CreatedAt = DateTime.UtcNow,
                PostId = commentViewModel.PostId,
                UserId = currentUser.Id

            };
            _context.PostComments.Add(comment);

            // Create notification
            await _context.SaveChangesAsync();
            // Send SignalR notification
            var receiverUserId = post.User.GoogleId ?? post.User.Username;
            if (receiverUserId != currentUser.GoogleId && receiverUserId != User.Identity.Name)
            {
                var notification = new Notification
                {
                    Message = $"{currentUser.Username} commented on your post.",
                    UserId = post.User.Id,
                    TriggeredByUserId = currentUser.Id,
                    PostId = commentViewModel.PostId
                };
                _context.Notifications.Add(notification);
                await _context.SaveChangesAsync();
                await _hubContext.Clients.User(receiverUserId).SendAsync("ReceiveNotification", new
                {
                    Id = notification.Id,
                    Message = notification.Message,
                    PostId = commentViewModel.PostId,
                    TriggeredByUser = new
                    {
                        Username = currentUser.Username,
                        ProfileImageUrl = currentUser.ProfileImageUrl // Ensure this exists
                    },
                    CreatedAt = notification.CreatedAt
                });
            }
            return Json(new { success = true, commentId = comment.Id, comment.Content, comment.CreatedAt, Username = currentUser.Username, CommentCount = post.CommentCount, ProfileImageUrl=currentUser.ProfileImageUrl });
        }


        [HttpGet]
        public async Task<IActionResult> GetUserProfileImage()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }

            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);
                if (user != null && !string.IsNullOrEmpty(user.ProfileImageUrl))
                {
                    return Json(new { imageUrl = user.ProfileImageUrl });
                }
            
            // Return a default profile image if user not found or no profile image exists
            return Json(new { imageUrl = "/images/default-avatar.png" });
        }



        [HttpGet]
        public async Task<IActionResult> GetNotifications(int pageNumber = 1, int pageSize = 10)
        {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);

            var notifications = await _context.Notifications
        .Where(n => n.UserId == user.Id)
        .OrderByDescending(n => n.CreatedAt)
        .Skip((pageNumber - 1) * pageSize)
        .Take(pageSize).Include(n => n.TriggeredByUser) // Eager load TriggeredByUser
        .ToListAsync();

            // Check if there are more notifications to load
            var hasMore = notifications.Count == pageSize;

            return Ok(new
            {
                Notifications = notifications.Select(n => new
                {
                    n.Id,
                    n.Message,
                    n.CreatedAt,
                    IsRead = n.IsRead,
                    TriggeredByUser = new
                    {
                        n.TriggeredByUser.Id,
                        n.TriggeredByUser.Username, // Assuming User model has Username
                        ProfileImageUrl = n.TriggeredByUser.ProfileImageUrl // Add if you have profile image URL
                    },
                    PostId=n.PostId
                }),
                HasMore = hasMore,
               
            });
        }
       

            [HttpPost]
            public async Task<IActionResult> MarkNotificationsAsRead([FromBody] int NotificationId)
            {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);

            var unreadNotification = await _context.Notifications
                    .SingleOrDefaultAsync(n => n.UserId == user.Id && !n.IsRead && n.Id == NotificationId);
                    

             if(unreadNotification!=null)
            {
                unreadNotification.IsRead = true;
                await _context.SaveChangesAsync();
            }


            

                return Ok(new { success = true });
            }

            [HttpGet]
            public async Task<IActionResult> GetUnreadNotificationCount()

            {
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == User.Identity.Name);

            var unreadCount = await _context.Notifications
                    .CountAsync(n => n.UserId == user.Id && !n.IsRead);

                return Ok(new { unreadCount });
            }
        [HttpGet]
        public async Task<IActionResult> PostDetails(int postId)
        {
            var post = _context.Posts
                .Include(p => p.User)
                .Include(p => p.Comments)
                .ThenInclude(p => p.User)
                .Include(p => p.Interactions) // Include Interactions within Posts
                .FirstOrDefault(p => p.Id == postId);

            if (post == null)
            {
                return NotFound();
            }

            var viewModel = new PostDetailsViewModel
            {
                PostId = post.Id,
                Content = post.Content,
                ImageUrl = post.ImageUrl,
                CreatedAt = post.CreatedAt,
                LikesCount = post.JaimeCount,
                Username = post.User.Username,
                UserProfileImageUrl = post.User.ProfileImageUrl,
                Comments = post.Comments.Select(c => new CommentView
                {
                    CommentId = c.Id,
                    Content = c.Content,
                    Username = c.User.Username,
                    UserProfileImageUrl = c.User.ProfileImageUrl,
                    CreatedAt = c.CreatedAt
                }).ToList()
            };

            return View("PostDetails",viewModel);
        }



        public class CommentViewModel
        {
            public int PostId { get; set; }
            public string Content { get; set; }
        }

        public class PostDto
        {
            public int Id { get; set; }
            public string Content { get; set; }
            public string ImageUrl { get; set; }
            public DateTime CreatedAt { get; set; }
            public UserDto User { get; set; } // Flattened User details
            public int JaimeCount {  get; set; }
            public int CommentCount { get; set; }
            public List<CommentDto> Comments { get; set; } // Add Comments property

        }
        public class CommentDto
        {
            public int Id { get; set; }
            public string Content { get; set; }
            public DateTime CreatedAt { get; set; }
            public string Username { get; set; }
            public string ProfileImageUrl { get; set; }
        }

        public class UserDto
        {
            public string Username { get; set; }
            public string ProfileImageUrl { get; set; }
        }


        public class AccueilViewModel
        {
            public User User { get; set; }
            public IEnumerable<Post> Posts { get; set; }
            public int TotalPosts { get; set; }
            public int PageNumber { get; set; }
            public int PageSize { get; set; }
        }


        public class ProfileAndPostViewModel
        {
            public UserViewModel User { get; set; }
            public CreatePostViewModel Post { get; set; }
            public List<PostViewModel> Posts { get; set; }
             public int TotalPosts { get; set; }
            public bool IsProfileOwner { get; set; }

        }
        public class PostViewModel
        {
            public int Id { get; set; }
            public string Content { get; set; }
            public string ImageUrl { get; set; }
            public DateTime CreatedAt { get; set; }
            public string Username { get; set; }
            public int JaimeCount { get; set; } // Count of Jaime interactions
            public int JadoreCount { get; set; } // Count of Jadore interactions
            public int CommentCount { get; set; } // Count of comments
            public List<CommentDto> Comments { get; set; }
            public string? HologramText { get; set; } // New property for hologram text
            public double? Latitude { get; set; } // Nullable for cases where it's not a hologram
            public double? Longitude { get; set; } // Nullable for cases where it's not a hologram
        }


        public class CreatePostViewModel
        {
            public string Username { get; set; } // Pass the logged-in user's username

            [Required(ErrorMessage = "Post content is required.")]
            public string Content { get; set; }

            public IFormFile Image { get; set; } // For the image upload
            public string ImagePrompt { get; set; } // For image generation prompt

            public string HologramText { get; set; } // New property for hologram text
            public string Latitude { get; set; } // Nullable for cases where it's not a hologram
            public string Longitude { get; set; } // Nullable for cases where it's not a hologram
            public string Type { get; set; } // Type of post (e.g., "text_image", "hologram", etc.)


        }
        public class ConversationViewModel
        {
            public int Id { get; set; } // ID of the conversation
            public string FriendUsername { get; set; }
            public string LastMessageContent { get; set; }
            public DateTime? LastMessageSentAt { get; set; }
            public string ImageProfile { get; set; }
            public bool HasUnreadMessages { get; set; }
        }

        public class SendMessageRequest
        {
            public string RecipientUsername { get; set; }
            public string Content { get; set; }
        }


        public class MessageViewModel
        {
            public string Content { get; set; }
            public DateTime SentAt { get; set; }
            public string SenderUsername { get; set; }
        }


        public class SearchUsersViewModel
        {
            public string SearchTerm { get; set; }
            public List<UserViewModel> Users { get; set; } = new List<UserViewModel>();
        }
        public class UserViewModel
        {
            public string Username { get; set; }
            public string Role { get; set; }
            public string ProfileImageUrl { get; set; }
            public string CoverImageUrl { get; set; }
            public List<FriendModel> Friends { get; set; }

            public int NumberOfFriends { get; set; } // Add this property


        }

        public class FriendRequestViewModel
        {
            public int Id { get; set; }
            public string SenderUsername { get; set; }
            public DateTime RequestedAt { get; set; }
            public string ProfilImage { get; set; }
        }
        public class FriendModel
        {
            public string Username { get; set; }
            public string ProfileImageUrl { get; set; }
        }
        public class ConversationDetailViewModel
        {
            public int ConversationId { get; set; } // Add this property

            public string FriendUsername { get; set; }
            public List<MessageViewModel> Messages { get; set; }
            public string ImageProfileFr { get; set; }
        }
        public class PostDetailsViewModel
        {
            public int PostId { get; set; }
            public string Content { get; set; }
            public string ImageUrl { get; set; }
            public DateTime CreatedAt { get; set; }
            public int LikesCount { get; set; }
            public string Username { get; set; }
            public string UserProfileImageUrl { get; set; }
            public List<CommentView> Comments { get; set; } = new List<CommentView>();
        }

        public class CommentView
        {
            public int CommentId { get; set; }
            public string Content { get; set; }
            public string Username { get; set; }
            public string UserProfileImageUrl { get; set; }
            public DateTime CreatedAt { get; set; }
        }
    }

}