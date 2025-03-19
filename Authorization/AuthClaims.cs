namespace AuthService.Authorization
{
    public static class AuthClaims
    {
        /// <summary>
        /// Defines system roles.
        /// </summary>
        public static class Roles
        {
            public const string Administrator = "Administrator";
            public const string Manager = "Manager";
            public const string StandardUser = "StandardUser";

            public static IReadOnlyList<string> AllRoles => [Administrator, Manager, StandardUser];
        }

        /// <summary>
        /// Defines system-wide permissions.
        /// </summary>
        public static class Permissions
        {
            public static class UserManagement
            {
                public const string View = "UserManagement.View";
                public const string Edit = "UserManagement.Edit";
                public const string Delete = "UserManagement.Delete";
            }

            public static class OrderManagement
            {
                public const string View = "OrderManagement.View";
                public const string Edit = "OrderManagement.Edit";
                public const string Delete = "OrderManagement.Delete";
            }

            public static IReadOnlySet<string> AllPermissions => new HashSet<string>
            {
                UserManagement.View, UserManagement.Edit, UserManagement.Delete,
                OrderManagement.View, OrderManagement.Edit, OrderManagement.Delete
            };
        }

        /// <summary>
        /// Maps roles to assigned permissions.
        /// </summary>
        public static class RolePermissionMapping
        {
            private static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> _rolePermissions = new Dictionary<string, IReadOnlySet<string>>
            {
                { Roles.Administrator, Permissions.AllPermissions },
                { Roles.Manager, new HashSet<string> { Permissions.UserManagement.View, Permissions.OrderManagement.View, Permissions.OrderManagement.Edit } },
                { Roles.StandardUser, new HashSet<string> { Permissions.UserManagement.View, Permissions.OrderManagement.View } }
            };

            /// <summary>
            /// Retrieves the permissions assigned to a given role.
            /// </summary>
            public static IReadOnlySet<string> GetPermissionsForRole(string role) =>
                _rolePermissions.TryGetValue(role, out var permissions) ? permissions : new HashSet<string>();

            /// <summary>
            /// Checks if a given role has a specific permission.
            /// </summary>
            public static bool HasPermission(string role, string permission) =>
                _rolePermissions.TryGetValue(role, out var permissions) && permissions.Contains(permission);
        }
    }
}
