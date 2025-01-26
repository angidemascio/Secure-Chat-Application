use rand::{rngs::ThreadRng, RngCore};

uint::construct_uint! {
	/// A 1024 bit unsigned integer.
	/// This is used to represent the large numbers used in the [`Yak`] protocol.
	pub struct U1024(16);
}

thread_local! {
	// YAK requires that both parties have an agreed upon prime number.
	// It is recommended that this happens separate from and before any communication. For
	// synchonicity, a static prime number is used.
	static LARGE_SHARED_PRIME: U1024 = U1024::from_dec_str("2666059058123518101548143651795902542003950378111894701790280012124011918017464857102059640892783997").unwrap();
}

/// Computes the modular exponentiation of a base to an exponent, modulo a modulus.
fn modular_exponentiation(mut base: U1024, mut exponent: U1024, modulus: U1024) -> U1024 {
	let mut result = U1024::one();

	while !exponent.is_zero() {
		if exponent.bit(0) {
			result = result.overflowing_mul(base).0 % modulus;
		}

		base = base.overflowing_mul(base).0 % modulus;
		exponent >>= 1;
	}

	result
}

/// Computes the modular exponentiation of a base to an exponent, to the shared prime.
fn fixed_exponentiation(base: U1024, exponent: U1024) -> U1024 {
	modular_exponentiation(base, exponent, LARGE_SHARED_PRIME.with(Clone::clone))
}

/// Pulls a random 1024 bit number from the RNG.
fn random_u1024(rng: &mut ThreadRng) -> U1024 {
	let mut data = [0; 128];

	rng.fill_bytes(&mut data);

	U1024::from_little_endian(&data)
}

/// Pulls a random 1024 bit number from the RNG, and reduces it modulo the shared prime.
fn random_field_u1024(rng: &mut ThreadRng) -> U1024 {
	random_u1024(rng) % LARGE_SHARED_PRIME.with(Clone::clone)
}

/// A [`Yak`] instance which can be used to generate a shared secret.
pub struct Yak {
	/// The random number generator used to generate the shared secret.
	/// This would ideally be a CSPRNG, but a thread local one is used for simplicity.
	/// Additionally, there is extra randomness in the fact that the generation is done
	/// across two different machines.
	rng: ThreadRng,

	/// The long term public key.
	key: U1024,

	/// The session key.
	session: U1024,
}

impl Yak {
	/// Creates a new [`Yak`] instance with a random long term key.
	pub fn new() -> Self {
		let mut rng = rand::thread_rng();
		let key = random_u1024(&mut rng);

		Self {
			rng,
			key,
			session: U1024::zero(),
		}
	}

	/// Starts a new session and returns the public key.
	pub fn start_session(&mut self) -> U1024 {
		self.session = random_field_u1024(&mut self.rng);

		fixed_exponentiation(U1024::from(2), self.key + self.session)
	}

	/// Computes the shared secret from the other party's public key
	/// and the user's own keys.
	pub fn compute_shared(&self, key: U1024) -> U1024 {
		fixed_exponentiation(key, self.key + self.session)
	}
}
