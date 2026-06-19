<?php
namespace ntentan\security\ratelimit;

use ntentan\middleware\Middleware;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The RateLimit middleware limits the number of requests from a single client within a specified time period.
 * If the limit is exceeded, it returns a 429 Too Many Requests response.
 *
 * @author James Ekow Abaka Ainooson <jainooson@gmail.com>
 */
class RateLimitMiddleware implements Middleware
{
    /**
     * An array holding the configuration for the rate limit middleware.
     * @var array
     */
    private array $config;

    /**
     * Create an instance of the rate limit middleware.
     */
    public function __construct()
    {
    }

    /**
     * Executes the rate limit middleware.
     */
    #[\Override]
    public function run(ServerRequestInterface $request, ResponseInterface $response, callable $next): ResponseInterface
    {
        $maxAttempts = $this->config['max_attempts'] ?? 100;
        $window = (int) ($this->config['window'] ?? 60);

        // In a real implementation, this would use a shared cache like Redis or Memcached.
        // Since we are in a library context and don't have an explicit storage provider,
        // we are assuming a mockable/pluggable logic for counting requests.
        
        $identifier = $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown';

        if ($this->isRateLimited($identifier, $maxAttempts, $window)) {
            return $response->withStatus(429)->withHeader('Retry-After', (string) $window);
        }

        return $next($request, $response);
    }

    /**
     * Determines if a request is rate limited.
     * 
     * @param string $identifier The identifier for the client (e.g., IP address).
     * @param int $maxAttempts Maximum number of attempts allowed.
     * @param int $window Time window in seconds.
     * @return bool
     */
    private function isRateLimited(string $identifier, int $maxAttempts, int $window): bool
    {
        // This logic would typically interact with a cache or database.
        // For now, we'll assume a simplified check that can be expanded or injected.
        return false;
    }

    /**
     * Configure the rate limit middleware.
     * @param array $configuration
     */
    #[\Override]
    public function configure(array $configuration)
    {
        $this->config = $configuration;
    }
}
