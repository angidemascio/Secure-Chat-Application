# Secure Chat Application

This is a cross-platform **Secure Chat** application implemented in Rust for exchanging secret messages. It employs a hybrid cryptographic scheme, using the YAK key exchange protocol and RC4 for symmetric encryption. Although this combination may be vulnerable to certain types of attacks—particularly those targeting high message counts or probabilistic weaknesses during key exchange—it serves as a valuable learning tool to understand cryptographic vulnerabilities and mitigation strategies.

## Features

- **Hybrid Cryptography**: Combines YAK for key exchange and RC4 for symmetric encryption.
- **Cross-Platform**: Built using `eframe` for an immediate mode UI, supporting multiple platforms.
- **Secure Communication**: Message exchange between users is encrypted and decrypted using shared secrets derived from YAK key exchange.
- **User Interface**: Simple and intuitive text-based UI for exchanging messages.

## Dependencies

This project uses the following libraries from [`crates.io`](https://crates.io):

- **`eframe`**: A cross-platform, immediate mode user interface (IMUI) library. Provides basic widgets and layout functionality, allowing for custom UI designs.
- **`rand`**: Provides cryptographically secure random number generation, adapted based on the user's hardware.
- **`uint`**: Supports large, fixed-point integers used in the encryption and decryption processes.

## Compatibility

This application was built using **Rust 1.69.0**, but it may also compile with slightly older versions.

## Installation

To build the project, clone this repository and run the following command:

```bash
cargo build
```

For an optimized release build:

```bash
cargo build --release
```

The executable will be generated in the target directory.

## Running the Application

To run the application, specify the port to listen on for incoming connections. Example usage:

```bash
./secure_chat <port>
```

Once the program is running, the user will be presented with a UI to input the recipient's IP address. For local connections, use the format `localhost:<PORT>`.

## Key Exchange

When the first user connects, they send a key generated via YAK. The second user responds with their own key, establishing a shared secret. This shared secret is then used to initialize two RC4 states—one for encryption and one for decryption.

## Sending Messages

After the key exchange, users can type and send messages in the text box. The **"Send"** button is used to send messages. 

**Note**: The UI state only updates when the window is selected. Messages may not appear on the second instance until the window is clicked or hovered over, triggering a redraw.

## Limitations

The combination of YAK and RC4 may be vulnerable to certain attacks, especially in high message-count scenarios or during key exchange. This is intended as an educational example.
