using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;
using Microsoft.VisualBasic;

public class User
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    public string Username { get; set; }
    public string? PasswordHash { get; set; }
    public string Role { get; set; }
    public string? GoogleId { get; set; } // Nullable, only populated for Google users
    public bool IsOnline { get; set; } = false;
    public string ProfileImageUrl { get; set; } = "/images/static/profile.png";
    public string CoverImageUrl { get; set; } = "/images/static/cover.png";  // Cover image URL
    public int NumberOfFriends { get; set; } // Add this property


    public ICollection<UserFriend> Friends { get; set; } = new List<UserFriend>();
    public ICollection<FriendRequest> FriendRequestsSent { get; set; } = new List<FriendRequest>();
    public ICollection<FriendRequest> FriendRequestsReceived { get; set; } = new List<FriendRequest>();
    public ICollection<Conversation> Conversations { get; set; } = new List<Conversation>();
    public ICollection<Post> Posts { get; set; } = new List<Post>();
    public ICollection<PostInteraction> Interactions { get; set; }
    public ICollection<PostComment> Comments { get; set; }
    public ICollection<Notification> Notifications { get; set; } = new List<Notification>();



}