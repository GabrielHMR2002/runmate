using Microsoft.EntityFrameworkCore;
using RunMate.Domain.Entities;
using RunMate.Infrastructure.Configurations.DomainConfiguration;

namespace RunMate.RunMate.Infrastructure.Persistence
{
    public class RunMateContext(DbContextOptions<RunMateContext> options) : DbContext(options)
    {
        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.ApplyConfiguration(new UserConfiguration());
        }
    }
}