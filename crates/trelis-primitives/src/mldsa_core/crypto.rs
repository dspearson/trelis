use hybrid_array::Array;
use sha3::{
    Shake128, Shake256,
    digest::{ExtendableOutput, XofReader},
};

use super::hash::{HashState, HashSuite};
use super::module_lattice::encode::ArraySize;

/// SHAKE hash state machine.
///
/// This enum represents the state of a SHAKE extendable output function,
/// which can either be absorbing input or squeezing output.
pub enum ShakeState<Shake: ExtendableOutput> {
    /// Absorbing input data into the sponge.
    Absorbing(Shake),
    /// Squeezing output data from the sponge.
    Squeezing(Shake::Reader),
}

impl<Shake: ExtendableOutput + Default> Default for ShakeState<Shake> {
    fn default() -> Self {
        Self::Absorbing(Shake::default())
    }
}

impl<Shake: ExtendableOutput + Default + Clone> ShakeState<Shake> {
    /// Absorb input data into the hash state.
    pub fn absorb(mut self, input: &[u8]) -> Self {
        match &mut self {
            Self::Absorbing(sponge) => sponge.update(input),
            Self::Squeezing(_) => unreachable!(),
        }

        self
    }

    /// Squeeze output data from the hash state.
    pub fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        match self {
            Self::Absorbing(sponge) => {
                // Clone required to satisfy borrow checker
                let mut reader = sponge.clone().finalize_xof();
                reader.read(output);
                *self = Self::Squeezing(reader);
            }
            Self::Squeezing(reader) => {
                reader.read(output.as_mut());
            }
        }

        self
    }

    /// Squeeze output data into a new array.
    pub fn squeeze_new<N: ArraySize>(&mut self) -> Array<u8, N> {
        let mut v = Array::default();
        self.squeeze(&mut v);
        v
    }
}

/// SHAKE128 hash state (G function in ML-DSA).
pub type G = ShakeState<Shake128>;
/// SHAKE256 hash state (H function in ML-DSA).
pub type H = ShakeState<Shake256>;

// Implement HashState for SHAKE128 (G)
impl HashState for ShakeState<Shake128> {
    fn absorb(self, input: &[u8]) -> Self {
        ShakeState::absorb(self, input)
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        ShakeState::squeeze(self, output)
    }
}

// Implement HashState for SHAKE256 (H)
impl HashState for ShakeState<Shake256> {
    fn absorb(self, input: &[u8]) -> Self {
        ShakeState::absorb(self, input)
    }

    fn squeeze(&mut self, output: &mut [u8]) -> &mut Self {
        ShakeState::squeeze(self, output)
    }
}

/// SHAKE-based hash suite (FIPS 204 standard)
#[derive(Debug, Clone, Copy, Default)]
pub struct ShakeSuite;

impl HashSuite for ShakeSuite {
    type G = ShakeState<Shake128>;
    type H = ShakeState<Shake256>;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mldsa_core::util::B32;
    use hex_literal::hex;

    #[test]
    fn g() {
        let input = b"hello world";
        let expected1 = hex!("3a9159f071e4dd1c8c4f968607c30942e120d8156b8b1e72e0d376e8871cb8b8");
        let expected2 = hex!("99072665674f26cc494a4bcf027c58267e8ee2da60e942759de86d2670bba1aa");

        let mut g = G::default().absorb(input);

        let mut actual = [0u8; 32];
        g.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = g.squeeze_new();
        assert_eq!(actual, expected2);
    }

    #[test]
    fn h() {
        let input = b"hello world";
        let expected1 = hex!("369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527");
        let expected2 = hex!("f4f3c2d55c2d46a29f2e945d469c3df27853a8735271f5cc2d9e889544357116");

        let mut h = H::default().absorb(input);

        let mut actual = [0u8; 32];
        h.squeeze(&mut actual);
        assert_eq!(actual, expected1);

        let actual: B32 = h.squeeze_new();
        assert_eq!(actual, expected2);
    }
}
