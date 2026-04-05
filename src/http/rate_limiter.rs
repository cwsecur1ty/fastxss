use governor::{Quota, RateLimiter as GovLimiter};
use std::num::NonZeroU32;

pub struct RateLimiter {
    limiter: GovLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>,
}

impl RateLimiter {
    pub fn new(requests_per_second: u32) -> Self {
        let rps = NonZeroU32::new(requests_per_second.max(1)).unwrap();
        let quota = Quota::per_second(rps);
        let limiter = GovLimiter::direct(quota);
        Self { limiter }
    }

    pub async fn wait(&self) {
        self.limiter.until_ready().await;
    }
}
