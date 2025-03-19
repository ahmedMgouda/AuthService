using AuthService.Models;
using Microsoft.EntityFrameworkCore;
using static AuthService.Authorization.AuthClaims;

namespace AuthService.Data
{
    public static class DataSeeder
    {
        public static async Task SeedAsync(IServiceProvider serviceProvider, ILogger logger)
        {
            using var scope = serviceProvider.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();

            logger.LogInformation("Starting database seeding...");

            try
            {
                // Uncomment the following line if using a persistent database (e.g., SQL Server) instead of an in-memory database.
                // await context.Database.MigrateAsync();

                if (await context.Users.AnyAsync() || await context.Roles.AnyAsync())
                {
                    logger.LogInformation("Skipping seeding: Users or roles already exist.");
                    return;
                }

                // Create Roles
                var roles = Roles.AllRoles
                    .Select(roleName => new Role { Name = roleName })
                    .ToList();
                await context.Roles.AddRangeAsync(roles);
                await context.SaveChangesAsync();

                // Create Permissions
                var permissions = Permissions.AllPermissions
                    .Select(permission => new Permission { Name = permission })
                    .ToList();
                await context.Permissions.AddRangeAsync(permissions);
                await context.SaveChangesAsync();

                // Link Permissions to Roles
                var rolePermissions = new List<RolePermission>();
                foreach (var role in roles)
                {
                    var assignedPermissions = RolePermissionMapping.GetPermissionsForRole(role.Name);
                    if (assignedPermissions != null)
                    {
                        foreach (var permissionName in assignedPermissions)
                        {
                            var permission = await context.Permissions.FirstOrDefaultAsync(p => p.Name == permissionName);
                            if (permission != null)
                            {
                                rolePermissions.Add(new RolePermission
                                {
                                    RoleId = role.Id,
                                    PermissionId = permission.Id
                                });
                            }
                        }
                    }
                }
                await context.RolePermissions.AddRangeAsync(rolePermissions);
                await context.SaveChangesAsync();

                // Create Admin and Standard User
                var adminUser = new User
                {
                    Email = "admin@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("Admin@123"),
                };

                var managerUser = new User
                {
                    Email = "manger@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("Manager@123"),
                };

                var standardUser = new User
                {
                    Email = "user@example.com",
                    PasswordHash = BCrypt.Net.BCrypt.HashPassword("User@123"),
                };

                await context.Users.AddRangeAsync(adminUser, standardUser);
                await context.SaveChangesAsync();

                // Assign Roles to Users
                var userRoles = new List<UserRole>
                {
                    new UserRole { UserId = adminUser.Id, RoleId = roles.First(r => r.Name == Roles.Administrator).Id },
                    new UserRole { UserId = managerUser.Id, RoleId = roles.First(r => r.Name == Roles.Manager).Id },
                    new UserRole { UserId = standardUser.Id, RoleId = roles.First(r => r.Name == Roles.StandardUser).Id }
                };

                await context.UserRoles.AddRangeAsync(userRoles);
                await context.SaveChangesAsync();

                logger.LogInformation("Database seeding completed successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred while seeding the database.");
            }
        }
    }
}
