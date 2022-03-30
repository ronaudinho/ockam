#![no_std]

use lazy_static::lazy_static;
use ockam_core::compat::sync::Mutex;
use rand::Rng;
use rand::SeedableRng;

/// A non-random number generator that returns consecutive numbers
/// starting from 0 to 255, wrapping back to 0.
pub fn getrandom_iota(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    for (index, byte) in destination.iter_mut().enumerate() {
        *byte = (index % 256) as u8;
    }
    Ok(())
}

/// A semi-random number generator with a fixed seed that is not
/// intended for production use.
///
/// Uses [`getrandom_pcg32()`].
///
/// WARNING: This implementation is neither random nor thread-local.
#[inline]
pub fn getrandom(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom_pcg32(destination)
}

/// A wrapper around the pcg32 SRNG
pub fn getrandom_pcg32(destination: &mut [u8]) -> Result<(), getrandom::Error> {
    if let Ok(mut state) = RNG_PCG32.lock() {
        match state.pcg32.try_fill(destination) {
            Ok(()) => Ok(()),
            Err(e) => Err(getrandom::Error::from(e.code().unwrap())),
        }
    } else {
        const ERROR_CODE: u32 = getrandom::Error::CUSTOM_START + 42; // TODO failed to acquire lock
        let code = core::num::NonZeroU32::new(ERROR_CODE).unwrap();
        Err(getrandom::Error::from(code))
    }
}

/// Reseed the semi-random number generator with the given seed
pub fn reseed(seed: u64) {
    if let Ok(mut state) = RNG_PCG32.lock() {
        state.reseed(seed);
    } else {
        panic!("Failed to acquire lock");
    }
}

/// Return the current seed for the semi-random number generator
pub fn seed() -> u64 {
    if let Ok(state) = RNG_PCG32.lock() {
        state.seed()
    } else {
        panic!("Failed to acquire lock");
    }
}

/// Global state for rand_pcg::Lcg64Xsh32 and its seed
struct GlobalState {
    pcg32: rand_pcg::Lcg64Xsh32,
    seed: u64,
}

impl GlobalState {
    /// Create a new semi-random number generator with the given seed
    fn new(seed: u64) -> Self {
        Self {
            pcg32: rand_pcg::Pcg32::seed_from_u64(seed),
            seed,
        }
    }

    /// Reseed the semi-random number generator
    fn reseed(&mut self, seed: u64) {
        self.pcg32 = rand_pcg::Pcg32::seed_from_u64(seed);
        self.seed = seed;
    }

    /// Return the current seed for the semi-random number generator
    fn seed(&self) -> u64 {
        self.seed
    }
}

lazy_static!(
    /// Holds the state of the semi-random number generator
    static ref RNG_PCG32: Mutex<GlobalState> = Mutex::new(GlobalState::new(0));
);
