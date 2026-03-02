use thiserror::Error;

#[derive(Debug, Error)]
pub enum LazyarpError {
    #[error("Insufficient permissions for raw socket access.\n\nTo run lazyarp, use one of:\n  sudo lazyarp\n  sudo setcap cap_net_raw+eip ./target/release/lazyarp && ./target/release/lazyarp")]
    InsufficientPermissions,

    #[error("No suitable network interface found. Ensure you have an active non-loopback interface with an IPv4 address.")]
    NoSuitableInterface,

    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("OUI lookup error: {0}")]
    OuiParse(#[from] csv::Error),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}
