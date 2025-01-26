/// An instance of the [`Rc4`] algorithm.
pub struct Rc4 {
	state: [u8; 256],
	i: u8,
	j: u8,
}

impl Rc4 {
	/// Creates a new [`Rc4`] instance.
	pub const fn new() -> Self {
		Self {
			state: [0; 256],
			i: 0,
			j: 0,
		}
	}

	/// Fetches the value at `i` in the state.
	fn fetch_i(&self) -> u8 {
		self.state[usize::from(self.i)]
	}

	/// Fetches the value at `j` in the state.
	fn fetch_j(&self) -> u8 {
		self.state[usize::from(self.j)]
	}

	/// Initializes the state with the given key.
	/// This key is generated from the key exchange protocol.
	pub fn initialize(&mut self, key: &[u8]) {
		for i in 0..=255 {
			self.state[usize::from(i)] = i;
		}

		let mut j = 0_u8;

		// Shuffle the state around.
		for i in 0..256 {
			j = j
				.wrapping_add(self.state[i])
				.wrapping_add(key[i % key.len()]);

			self.state.swap(i, j.into());
		}

		self.i = 0;
		self.j = 0;

		// Discard the first 3072 bytes of the keystream.
		// This is advised in the RC4 specification as a way to
		// avoid the first few bytes being predictable.
		for _ in 0..3072 {
			self.next();
		}
	}

	/// Generates the next byte of the keystream.
	/// This is the core of the RC4 algorithm.
	fn next(&mut self) -> u8 {
		self.i = self.i.wrapping_add(1);
		self.j = self.j.wrapping_add(self.fetch_i());

		self.state.swap(self.i.into(), self.j.into());

		let result = self.fetch_i().wrapping_add(self.fetch_j());

		self.state[usize::from(result)]
	}

	/// Processes the given data with the keystream by XORing it.
	pub fn process(&mut self, data: &mut [u8]) {
		data.iter_mut().for_each(|byte| *byte ^= self.next());
	}
}
