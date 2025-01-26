use std::{
	io::{Read, Write},
	net::{TcpStream, ToSocketAddrs},
};

use crate::{rc4::Rc4, yak::U1024};

/// Dumps the key to a byte array.
fn key_to_bytes(key: U1024) -> [u8; 128] {
	let mut data = [0; 128];

	key.to_little_endian(&mut data);

	data
}

/// A packet that can be sent over the network.
pub enum Packet {
	/// The initial packet that sets up the session key.
	Acknowledge { key: Box<U1024> },

	/// A message that is sent to the recipient.
	Message { data: String },

	/// A packet that indicates that the sender is leaving.
	Leave,
}

impl Packet {
	/// Returns the discriminant of the packet.
	const fn discriminant(&self) -> u8 {
		match self {
			Self::Acknowledge { .. } => 0,
			Self::Message { .. } => 1,
			Self::Leave => 2,
		}
	}

	/// Serializes the packet to the writer as a byte array.
	fn serialize(&self, writer: &mut dyn Write) {
		writer.write_all(&[self.discriminant()]).unwrap();

		match self {
			Self::Acknowledge { key } => {
				let bytes = key_to_bytes(**key);

				writer.write_all(&bytes).unwrap();
			}
			Self::Message { data } => {
				let len = data.len();

				writer.write_all(&len.to_le_bytes()).unwrap();
				writer.write_all(data.as_bytes()).unwrap();
			}
			Self::Leave => {}
		}
	}

	/// Tries to deserialize a packet from the reader.
	fn try_deserialize(reader: &mut dyn Read) -> Option<(Self, usize)> {
		const LEN: usize = std::mem::size_of::<usize>();

		let mut buffer = [0; 128];

		reader.read_exact(&mut buffer[..1]).ok()?;

		let data = match buffer[0] {
			0 => {
				reader.read_exact(&mut buffer).ok()?;

				let key = U1024::from_little_endian(&buffer).into();

				(Self::Acknowledge { key }, 128)
			}
			1 => {
				reader.read_exact(&mut buffer[..LEN]).ok()?;

				let len = usize::from_le_bytes(buffer[..LEN].try_into().unwrap());

				let mut data = vec![0; len];

				reader.read_exact(&mut data).ok()?;

				let data = String::from_utf8(data).ok()?;

				(Self::Message { data }, LEN + len)
			}
			2 => (Self::Leave, 0),
			_ => return None,
		};

		Some(data)
	}
}

/// A session that can be used to send and receive packets.
/// It also handles the encryption and decryption of the packets.
/// Two RC4 instances are used to solve the problem of the RC4 stream being
/// desynchronized upon sending packets at the same time.
pub struct Session {
	/// The underlying TCP stream.
	stream: TcpStream,

	/// The RC4 cipher used to encrypt outgoing packets.
	rc4_out: Rc4,

	/// The RC4 cipher used to decrypt incoming packets.
	rc4_in: Rc4,

	/// The buffer used to store the packet data.
	buffer: Vec<u8>,
}

impl Session {
	/// Creates a new session from a TCP stream.
	pub fn from_stream(stream: TcpStream) -> std::io::Result<Self> {
		stream.set_nonblocking(true)?;
		stream.set_nodelay(true)?;

		Ok(Self {
			stream,
			rc4_out: Rc4::new(),
			rc4_in: Rc4::new(),
			buffer: Vec::new(),
		})
	}

	/// Creates a new session from a recipient address.
	pub fn from_recipient<A: ToSocketAddrs>(socket: A) -> std::io::Result<Self> {
		TcpStream::connect(socket).and_then(Self::from_stream)
	}

	/// Reads a packet from the stream, if any.
	pub fn read(&mut self) -> Option<Packet> {
		let last = self.buffer.len();
		let _result = self.stream.read_to_end(&mut self.buffer);

		if self.buffer.is_empty() {
			return None;
		}

		println!("IN: {}", String::from_utf8_lossy(&self.buffer[last..]));

		self.rc4_in.process(&mut self.buffer[last..]);

		let (packet, size) = Packet::try_deserialize(&mut self.buffer.as_slice())?;

		self.buffer.drain(..=size);

		Some(packet)
	}

	/// Writes a packet to the stream.
	pub fn write(&mut self, data: &Packet) {
		let last = self.buffer.len();

		data.serialize(&mut self.buffer);

		self.rc4_out.process(&mut self.buffer[last..]);

		println!("OUT: {}", String::from_utf8_lossy(&self.buffer[last..]));

		self.stream.write_all(&self.buffer[last..]).unwrap();
		self.buffer.drain(last..);
	}

	/// Sets the session key and initializes the RC4 ciphers.
	pub fn secure(&mut self, key: U1024) {
		let bytes = key_to_bytes(key);

		self.rc4_out.initialize(&bytes);
		self.rc4_in.initialize(&bytes);
	}
}
