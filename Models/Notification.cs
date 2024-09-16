using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

public class Notification
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }
    public string Message { get; set; }

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public bool IsRead { get; set; } = false;
    public int UserId { get; set; }
    public User User { get; set; }
    public int TriggeredByUserId { get; set; }
    public User TriggeredByUser { get; set; }
    public int? PostId { get; set; }
}
