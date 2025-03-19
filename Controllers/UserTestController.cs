using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using static AuthService.Authorization.AuthClaims;

namespace AuthService.Controllers
{
    [Route("api/user-test")]
    [ApiController]
    public class UserTestController : ControllerBase
    {
        /// <summary>
        /// Accessible to any authenticated user.
        /// </summary>
        [Authorize]
        [HttpGet("authenticated")]
        public IActionResult AuthenticatedUser()
        {
            return Ok("This endpoint is accessible to any authenticated user.");
        }

        /// <summary>
        /// Requires the Administrator role.
        /// </summary>
        [Authorize(Roles = Roles.Administrator)]
        [HttpGet("admin")]
        public IActionResult AdminAccess()
        {
            return Ok("Only administrators can access this endpoint.");
        }

        /// <summary>
        /// Requires the Manager role.
        /// </summary>
        [Authorize(Roles = Roles.Manager)]
        [HttpGet("manager")]
        public IActionResult ManagerAccess()
        {
            return Ok("Only managers can access this endpoint.");
        }

        /// <summary>
        /// Requires the StandardUser role.
        /// </summary>
        [Authorize(Roles = Roles.StandardUser)]
        [HttpGet("user")]
        public IActionResult StandardUserAccess()
        {
            return Ok("Only standard users can access this endpoint.");
        }

        /// <summary>
        /// Requires the UserManagement.View permission.
        /// </summary>
        [Authorize(Policy = Permissions.UserManagement.View)]
        [HttpGet("view-users")]
        public IActionResult ViewUsers()
        {
            return Ok("You have permission to view users.");
        }

        /// <summary>
        /// Requires the OrderManagement.Edit permission.
        /// </summary>
        [Authorize(Policy = Permissions.OrderManagement.Edit)]
        [HttpGet("edit-orders")]
        public IActionResult EditOrders()
        {
            return Ok("You have permission to edit orders.");
        }
    }
}
