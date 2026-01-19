use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tokio::sync::RwLock;

/// Configuration for rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed in the window
    pub max_requests: u32,
    /// Time window for rate limiting
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 5,
            window: Duration::from_secs(60),
        }
    }
}

/// Entry for tracking rate limit state
#[derive(Debug, Clone)]
struct RateLimitEntry {
    count: u32,
    window_start: Instant,
}

/// In-memory rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiter {
    config: RateLimitConfig,
    entries: Arc<RwLock<HashMap<IpAddr, RateLimitEntry>>>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check if a request from the given IP should be allowed
    /// Returns Ok(remaining) if allowed, Err(retry_after) if rate limited
    pub async fn check(&self, ip: IpAddr) -> Result<u32, Duration> {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        let entry = entries.entry(ip).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if it has expired
        if now.duration_since(entry.window_start) >= self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check if we're over the limit
        if entry.count >= self.config.max_requests {
            let retry_after = self.config.window - now.duration_since(entry.window_start);
            return Err(retry_after);
        }

        // Increment counter
        entry.count += 1;
        let remaining = self.config.max_requests - entry.count;

        Ok(remaining)
    }

    /// Record a failed attempt (e.g., failed login) which may have different limits
    pub async fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        let entry = entries.entry(ip).or_insert(RateLimitEntry {
            count: 0,
            window_start: now,
        });

        // Reset window if it has expired
        if now.duration_since(entry.window_start) >= self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        entry.count += 1;
    }

    /// Clean up expired entries (call periodically)
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut entries = self.entries.write().await;

        entries.retain(|_, entry| now.duration_since(entry.window_start) < self.config.window);
    }
}

/// Error returned when rate limit is exceeded
#[derive(Debug)]
pub struct RateLimitExceeded {
    pub retry_after: Duration,
}

impl IntoResponse for RateLimitExceeded {
    fn into_response(self) -> Response {
        let retry_after_secs = self.retry_after.as_secs();
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("Retry-After", retry_after_secs.to_string())],
            format!("Rate limit exceeded. Retry after {} seconds.", retry_after_secs),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_rate_limiter_allows_requests_under_limit() {
        let config = RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First 3 requests should succeed
        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_ok());
        assert!(limiter.check(ip).await.is_ok());

        // 4th request should fail
        assert!(limiter.check(ip).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_returns_remaining() {
        let config = RateLimitConfig {
            max_requests: 3,
            window: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        assert_eq!(limiter.check(ip).await.unwrap(), 2);
        assert_eq!(limiter.check(ip).await.unwrap(), 1);
        assert_eq!(limiter.check(ip).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_rate_limiter_different_ips() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_secs(60),
        };
        let limiter = RateLimiter::new(config);
        let ip1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));

        // Each IP gets its own limit
        assert!(limiter.check(ip1).await.is_ok());
        assert!(limiter.check(ip2).await.is_ok());

        // Both should now be rate limited
        assert!(limiter.check(ip1).await.is_err());
        assert!(limiter.check(ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_window_reset() {
        let config = RateLimitConfig {
            max_requests: 1,
            window: Duration::from_millis(50),
        };
        let limiter = RateLimiter::new(config);
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // First request succeeds
        assert!(limiter.check(ip).await.is_ok());
        // Second request fails
        assert!(limiter.check(ip).await.is_err());

        // Wait for window to reset
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Now should succeed again
        assert!(limiter.check(ip).await.is_ok());
    }
}
