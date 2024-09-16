using Microsoft.EntityFrameworkCore;

public class ApplicationDbContext : DbContext
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
    public DbSet<User> Users { get; set; }
    public DbSet<UserFriend> UserFriends { get; set; }
    public DbSet<FriendRequest> FriendRequests { get; set; }
    public DbSet<Conversation> Conversations { get; set; }
    public DbSet<Message> Messages { get; set; }
    public DbSet<Post> Posts { get; set; }
    public DbSet<PostInteraction> PostInteractions { get; set; }
    public DbSet<PostComment> PostComments { get; set; }
    public DbSet<Notification> Notifications { get; set; }
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        // Configure many-to-many relationship for UserFriends
        modelBuilder.Entity<UserFriend>()
            .HasOne(uf => uf.User)
            .WithMany(u => u.Friends)
            .HasForeignKey(uf => uf.UserId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<UserFriend>()
            .HasOne(uf => uf.Friend)
            .WithMany()
            .HasForeignKey(uf => uf.FriendId)
            .OnDelete(DeleteBehavior.Restrict);

        // Configure one-to-many relationship for FriendRequests
        modelBuilder.Entity<FriendRequest>()
            .HasOne(fr => fr.Sender)
            .WithMany(u => u.FriendRequestsSent)
            .HasForeignKey(fr => fr.SenderId)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<FriendRequest>()
            .HasOne(fr => fr.Receiver)
            .WithMany(u => u.FriendRequestsReceived)
            .HasForeignKey(fr => fr.ReceiverId)
            .OnDelete(DeleteBehavior.Restrict);

        // Configure one-to-many relationship for Conversations
        modelBuilder.Entity<Conversation>()
            .HasMany(c => c.Messages)
            .WithOne(m => m.Conversation)
            .HasForeignKey(m => m.ConversationId);

        // Configure many-to-one relationship for Messages
        modelBuilder.Entity<Message>()
            .HasOne(m => m.Sender)
            .WithMany()
            .HasForeignKey(m => m.SenderId)
            .OnDelete(DeleteBehavior.Restrict);

        // Configure many-to-one relationship for Conversations with Users
        modelBuilder.Entity<Conversation>()
            .HasOne(c => c.User1)
            .WithMany(u => u.Conversations)
            .HasForeignKey(c => c.User1Id)
            .OnDelete(DeleteBehavior.Restrict);

        modelBuilder.Entity<Conversation>()
            .HasOne(c => c.User2)
            .WithMany()
            .HasForeignKey(c => c.User2Id)
            .OnDelete(DeleteBehavior.Restrict);

        // Configure the Post-User relationship
        modelBuilder.Entity<Post>()
            .HasOne(p => p.User)
            .WithMany(u => u.Posts)
            .HasForeignKey(p => p.UserId);

        // Configure the PostInteraction-User relationship
        modelBuilder.Entity<PostInteraction>()
            .HasOne(pi => pi.User)
            .WithMany(u => u.Interactions)
            .HasForeignKey(pi => pi.UserId);

        // Configure the PostInteraction-Post relationship
        modelBuilder.Entity<PostInteraction>()
            .HasOne(pi => pi.Post)
            .WithMany(p => p.Interactions)
            .HasForeignKey(pi => pi.PostId);

        // Configure the PostComment-User relationship
        modelBuilder.Entity<PostComment>()
            .HasOne(pc => pc.User)
            .WithMany(u => u.Comments)
            .HasForeignKey(pc => pc.UserId);

        // Configure the PostComment-Post relationship
        modelBuilder.Entity<PostComment>()
            .HasOne(pc => pc.Post)
            .WithMany(p => p.Comments)
            .HasForeignKey(pc => pc.PostId);
        // Configure User and Notifications relationship
        modelBuilder.Entity<User>()
            .HasMany(u => u.Notifications)
            .WithOne(n => n.User)
            .HasForeignKey(n => n.UserId)
            .OnDelete(DeleteBehavior.Cascade); // Cascade or restrict based on your requirement

        // Configure the relationship for notifications triggered by a user
        modelBuilder.Entity<Notification>()
            .HasOne(n => n.TriggeredByUser)
            .WithMany() // Assuming TriggeredByUser does not have a collection of notifications
            .HasForeignKey(n => n.TriggeredByUserId)
            .OnDelete(DeleteBehavior.Restrict); // Cascade or restrict based on your requirement

    }
}

