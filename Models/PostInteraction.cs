using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public enum InteractionType
{
    Jaime,
    Jadore
}

public class PostInteraction
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]

    public int Id { get; set; }

    // Foreign key for Post
    public int PostId { get; set; }
    public Post Post { get; set; }

    // Foreign key for User
    public int UserId { get; set; }
    public User User { get; set; }

    // Type of interaction
    public InteractionType InteractionType { get; set; }

    public DateTime InteractedAt { get; set; } = DateTime.Now;
}
