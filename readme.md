# Encrypted UDP Example

An example of using crypto_box public key encryption to do an authenticated connection over UDP and start communicating with crypto_secret_box secret key encryption.

## Usage

Generate a pair of keys in a "server" directory, and a separate "client" directory.  This creates a public.key and private.key keypair for each.
```udpbox generate```

Copy the server's public.key to the client's folder and name it client.key.  Copy the client's public.key to the server's folder and name it server.key.

Run the server from the server Generate a pair of keys in a "server" directory.
:
```udpbox serve 44321```

Run the client from the client Generate a pair of keys in a "server" directory.  It will try to connect to 127.0.0.1:44321
:
```udpbox connect```

## Requirements

libsodium
