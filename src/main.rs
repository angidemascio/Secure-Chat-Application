use std::{
	fmt::{Arguments, Write},
	net::{SocketAddr, TcpListener},
};

use eframe::{
	egui::{Button, CentralPanel, Context, Grid, TextEdit, Vec2},
	epaint::Color32,
	Frame, NativeOptions,
};

use self::{
	session::{Packet, Session},
	yak::Yak,
};

mod rc4;
mod session;
mod yak;

/// The status shown to the user in the UI.
#[derive(Clone, Copy)]
enum Status {
	Active,
	Inactive,
}

impl Status {
	/// Returns `true` if the status is [`Status::Active`].
	const fn is_active(self) -> bool {
		matches!(self, Self::Active)
	}

	/// Returns `true` if the status is [`Status::Inactive`].
	const fn is_inactive(self) -> bool {
		matches!(self, Self::Inactive)
	}

	/// Returns the color and label for the status.
	const fn as_label(self) -> (Color32, &'static str) {
		match self {
			Self::Active => (Color32::LIGHT_GREEN, "Active"),
			Self::Inactive => (Color32::LIGHT_RED, "Inactive"),
		}
	}

	/// Returns the label for the button to toggle the connection.
	const fn as_set_reset(self) -> &'static str {
		match self {
			Self::Active => "Reset",
			Self::Inactive => "Set",
		}
	}
}

/// The main application.
///
/// It consists of the [`Yak`] instance, the [`TcpListener`] for incoming connections, the current
/// [`Session`], the recipient address, the message box, and the output label.
struct Application {
	/// The [`Yak`] instance used to compute the keys.
	yak: Yak,

	/// The [`TcpListener`] for incoming connections.
	server: TcpListener,

	/// The current [`Session`] for transmitting data.
	session: Option<Session>,

	/// Various information and state for the UI.
	recipient: String,
	message_box: String,
	output_label: String,
}

impl Application {
	/// Creates a new [`Application`] instance with the given [`TcpListener`]
	/// already bound to the port.
	fn new(server: TcpListener) -> Self {
		Self {
			yak: Yak::new(),
			server,
			session: None,
			recipient: String::new(),
			message_box: String::new(),
			output_label: String::new(),
		}
	}

	/// Logs the given arguments to the output label. This is
	/// shown to the user in the UI.
	fn log(&mut self, name: &str, arguments: Arguments) {
		let mut buffer = String::new();

		writeln!(&mut buffer, "[{name}] {arguments}").unwrap();

		self.output_label = buffer + &self.output_label;
	}

	/// Sets the current [`Session`] to the given one.
	/// This will also send an [`Packet::Acknowledge`] packet to the
	/// recipient.
	fn set_session(&mut self, mut session: Session) {
		let key = self.yak.start_session().into();

		session.write(&Packet::Acknowledge { key });

		self.session = Some(session);
	}

	/// Tries to accept an incoming connection if not
	/// already connected to a recipient.
	fn try_accept(&mut self) {
		if self.session.is_some() {
			return;
		}

		if let Ok((stream, address)) = self.server.accept() {
			match Session::from_stream(stream) {
				Ok(session) => {
					self.log("net", format_args!("receiving from {address}"));

					self.set_session(session);
				}
				Err(error) => {
					self.log("net", format_args!("{error} from {address}"));
				}
			}
		}
	}

	/// Disconnects from the current recipient.
	/// This will also send a [`Packet::Leave`] packet to the recipient.
	fn disconnect(&mut self) {
		if let Some(mut session) = self.session.take() {
			session.write(&Packet::Leave);
		}
	}

	/// Tries to connect to the recipient.
	/// This will also send an [`Packet::Acknowledge`] packet to the recipient.
	fn connect(&mut self) {
		match Session::from_recipient(&self.recipient) {
			Ok(session) => self.set_session(session),
			Err(error) => self.log("net", format_args!("failed to connect: {error}")),
		}
	}

	/// Tries to send the message box to the recipient.
	fn send(&mut self) {
		if let Some(session) = &mut self.session {
			let packet = Packet::Message {
				data: std::mem::take(&mut self.message_box),
			};

			session.write(&packet);
		}
	}

	/// Tries to process packets from the recipient.
	/// Returns the new status of the connection.
	fn try_process(&mut self) -> Status {
		if let Some(mut session) = std::mem::take(&mut self.session) {
			while let Some(data) = session.read() {
				match data {
					Packet::Acknowledge { key } => {
						let key = self.yak.compute_shared(*key);

						session.secure(key);

						println!("KEY: {key}");

						self.log("net", format_args!("keys have been exchanged"));
					}
					Packet::Message { data } => {
						self.log("msg", format_args!("{data}"));
					}
					Packet::Leave => {
						self.log("net", format_args!("the recipient has disconnected"));

						return Status::Inactive;
					}
				}
			}

			self.session = Some(session);

			Status::Active
		} else {
			Status::Inactive
		}
	}
}

impl eframe::App for Application {
	fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
		self.try_accept();

		let status = self.try_process();

		CentralPanel::default().show(ctx, |ui| {
			let grid = Grid::new("Info").num_columns(3).min_col_width(50.0);

			ui.separator();

			grid.show(ui, |ui| {
				ui.label("Status");

				let (color, label) = status.as_label();

				ui.colored_label(color, label);

				ui.end_row();

				ui.label("Recipient");

				let button = Button::new(status.as_set_reset()).min_size(Vec2::new(50.0, 0.0));

				if ui.add(button).clicked() {
					if status.is_inactive() {
						self.connect();
					} else {
						self.disconnect();
					}
				}

				let recipient = TextEdit::singleline(&mut self.recipient).hint_text("Recipient");

				ui.add_enabled(status.is_inactive(), recipient)
			});

			ui.separator();

			ui.vertical_centered_justified(|ui| {
				let button = Button::new("Send").min_size(Vec2::new(50.0, 0.0));
				let data = TextEdit::multiline(&mut self.message_box).hint_text("Message");

				ui.add(data);

				let active = status.is_active() && !self.message_box.is_empty();

				if ui.add_enabled(active, button).clicked() {
					self.send();
				}
			});

			ui.separator();

			ui.vertical_centered_justified(|ui| {
				let text = TextEdit::multiline(&mut self.output_label)
					.desired_rows(0)
					.hint_text("Output");

				ui.add_enabled(false, text);
			})
		});
	}
}

/// Loads the server from the given port.
/// This will also set the server to non-blocking mode so
/// that it can be periodically polled.
fn load_server(port: u16) -> TcpListener {
	let socket = SocketAddr::from(([127, 0, 0, 1], port));
	let server = TcpListener::bind(socket).expect("could not bind to socket");

	server.set_nonblocking(true).unwrap();

	server
}

/// The entry point.
/// It parses the command line arguments and starts the application.
fn main() -> Result<(), eframe::Error> {
	let argument = std::env::args().nth(1).expect("please specify a port");
	let server = load_server(argument.parse().expect("could not parse port"));

	let options = NativeOptions {
		initial_window_size: Some(Vec2::new(400.0, 500.0)),
		resizable: false,
		..Default::default()
	};

	eframe::run_native(
		"Secure Sender",
		options,
		Box::new(move |_cc| Box::new(Application::new(server))),
	)
}
