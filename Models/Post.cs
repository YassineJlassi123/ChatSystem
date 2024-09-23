using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class Post
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]

    public int Id { get; set; }
    public string? Content { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // New property for storing the image path
    public string? ImageUrl { get; set; }

    // Foreign key for User
    public int UserId { get; set; }
    public User User { get; set; }

    // Relationships
    public ICollection<PostInteraction> Interactions { get; set; } = new List<PostInteraction>();
    public ICollection<PostComment> Comments { get; set; } = new List<PostComment>();

    // Computed properties for interaction counts
    public int JaimeCount => Interactions.Count(i => i.InteractionType == InteractionType.Jaime);
    public int JadoreCount => Interactions.Count(i => i.InteractionType == InteractionType.Jadore);
    public int CommentCount => Comments.Count;
    public string? HologramText { get; set; } // New property for hologram text
    public double? Latitude { get; set; } // Nullable for cases where it's not a hologram
    public double? Longitude { get; set; } // Nullable for cases where it's not a hologram
}
