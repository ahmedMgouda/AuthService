using System.Collections.Concurrent;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace AuthService.Authorization
{
    /// <summary>
    /// Custom policy provider that dynamically generates authorization policies based on the requested policy name.
    /// If the policy exists, it is returned from cache; otherwise, a new policy is created.
    /// </summary>
    public class PermissionPolicyProvider : IAuthorizationPolicyProvider
    {
        private readonly DefaultAuthorizationPolicyProvider _fallbackPolicyProvider;
        private readonly ILogger<PermissionPolicyProvider> _logger;

        /// <summary>
        /// Uses a ConcurrentDictionary with Lazy<Task<T>> to ensure thread safety  
        /// and prevent race conditions when creating and caching policies.
        /// </summary>
        private readonly ConcurrentDictionary<string, Lazy<Task<AuthorizationPolicy?>>> _policyCache = new();

        public PermissionPolicyProvider(
            IOptions<AuthorizationOptions> options,
            ILogger<PermissionPolicyProvider> logger)
        {
            _fallbackPolicyProvider = new DefaultAuthorizationPolicyProvider(options);
            _logger = logger;
        }

        /// <summary>
        /// Gets the default authorization policy.
        /// This policy is used when an [Authorize] attribute is applied without specifying a policy name.
        /// </summary>
        public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
            => _fallbackPolicyProvider.GetDefaultPolicyAsync();

        /// <summary>
        /// Gets the fallback authorization policy.
        /// This policy applies to all requests, even those without [Authorize].
        /// </summary>
        public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
            => _fallbackPolicyProvider.GetFallbackPolicyAsync();

        /// <summary>
        /// Retrieves or creates a dynamic authorization policy based on the given policy name.
        /// </summary>
        public async Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
        {
            try
            {
                var lazyPolicy = _policyCache.GetOrAdd(policyName, _ =>
                    new Lazy<Task<AuthorizationPolicy?>>(() => CreatePolicyAsync(policyName))
                );

                var policy = await lazyPolicy.Value;

                if (policy == null)
                {
                    RemovePolicyFromCache(policyName);
                }

                return policy;
            }
            catch (Exception ex)
            {
                RemovePolicyFromCache(policyName);
                _logger.LogError(ex, "Error retrieving policy '{PolicyName}', removing from cache.", policyName);
                return null;
            }
        }

        /// <summary>
        /// Creates a new authorization policy dynamically.
        /// </summary>
        private async Task<AuthorizationPolicy?> CreatePolicyAsync(string policyName)
        {
            try
            {
                var predefinedPolicy = await _fallbackPolicyProvider.GetPolicyAsync(policyName);
                if (predefinedPolicy != null)
                {
                    _logger.LogDebug("Policy '{PolicyName}' is a predefined policy.", policyName);
                    return predefinedPolicy;
                }

                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .AddRequirements(new PermissionRequirement(policyName))
                    .Build();

                _logger.LogInformation("Policy '{PolicyName}' created dynamically. Total Cached Policies: {CacheCount}", policyName, _policyCache.Count);
                return policy;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating policy '{PolicyName}'.", policyName);
                return null;
            }
        }

        /// <summary>
        /// Safely removes a policy from the cache if it fails to load or create.
        /// </summary>
        private void RemovePolicyFromCache(string policyName)
        {
            if (_policyCache.TryRemove(policyName, out _))
            {
                _logger.LogWarning("Policy '{PolicyName}' removed from cache. Total Cached Policies: {CacheCount}", policyName, _policyCache.Count);
            }
        }
    }
}
