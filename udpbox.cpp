#include <iostream>

// libsodium
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sodium.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <fstream>
#include <exception>
#include <vector>
#include <string.h>

struct CryptoBoxKeypair {
    u_char publicKey[crypto_box_PUBLICKEYBYTES];
    u_char secretKey[crypto_box_SECRETKEYBYTES];
};

bool tryLoadKeys(CryptoBoxKeypair & keypair) {
    bool loaded = false;
    FILE * publicfile = fopen("public.key", "rb");
    if (!publicfile) {
        std::cout << "failed to open public.key\n";
    }
    FILE * secretfile = fopen("secret.key", "rb");
    if (!secretfile) {
        std::cout << "failed to open secret.key\n";
    }
    size_t pubKeySize;
    if (1 != fread(keypair.publicKey, sizeof(keypair.publicKey), 1, publicfile)) {
        std::cout << "failed to read " << sizeof(keypair.publicKey) << " bytes from public.key\n";
        goto close;
    }
    if (1 != fread(keypair.secretKey, sizeof(keypair.secretKey), 1, secretfile)) {
        std::cout << "failed to read " << sizeof(keypair.secretKey) << " bytes from secret.key\n";
        goto close;
    }
    loaded = true;

    close:
    if (publicfile) fclose(publicfile);
    if (secretfile) fclose(secretfile);
    return loaded;
}

bool tryLoadPublicKey(const char * publicKeyFilename, CryptoBoxKeypair & keypair) {
    bool loaded = false;
    FILE * publicfile = fopen(publicKeyFilename, "rb");
    if (!publicfile) {
        std::cout << "failed to open public key file " << publicKeyFilename << "\n";
        goto close;
    }
    if (1 != fread(keypair.publicKey, sizeof(keypair.publicKey), 1, publicfile)) {
        std::cout << "failed to read " << sizeof(keypair.publicKey) << " bytes from " << publicKeyFilename << "\n";
        goto close;
    }
    loaded = true;

    close:
    if (publicfile) fclose(publicfile);
    return loaded;
}

struct CryptoBoxSender {
    CryptoBoxKeypair senderKeypair;
    CryptoBoxKeypair recipientKeypair;
    unsigned char clientId;
    unsigned char nonce[crypto_box_NONCEBYTES];
    CryptoBoxSender(const char * recipientKeyFilename, unsigned char clientId) : clientId(clientId) {
        if (!tryLoadKeys(senderKeypair) || !tryLoadPublicKey(recipientKeyFilename, recipientKeypair)) {
            throw std::runtime_error("cannot create cryptobox sender");
        }
        randombytes_buf(nonce, sizeof nonce);
    }
    void encrypt(std::vector<u_char> & payload) {
        size_t messageLength = payload.size();
        payload.resize(payload.size() + crypto_box_MACBYTES);
        if (-1 == crypto_box_easy(payload.data(), payload.data(), messageLength, nonce, recipientKeypair.publicKey, senderKeypair.secretKey)) {
            throw std::runtime_error("failed to encrypt");
        }
    }
    void appendNonceAndId(std::vector<u_char> & payload) {
        size_t nonceOffset = payload.size();
        payload.resize(nonceOffset + crypto_box_NONCEBYTES + 1);
        memcpy(payload.data()+nonceOffset, nonce, crypto_box_NONCEBYTES);
        payload.back() = clientId;
    }
};

struct CryptoBoxRecipient {
    CryptoBoxKeypair recipientKeypair;
    struct {
        bool loaded = false;
        CryptoBoxKeypair publicKey;
    } senders[16];
    CryptoBoxRecipient() {
        if (!tryLoadKeys(recipientKeypair)) {
            throw std::runtime_error("cannot create cryptobox recipient");
        }
        for (auto & sender : senders) {
            sender.loaded = false;
        }
    }
    bool tryAddSender(u_char id, const char * publicKeyFilename) {
        if (id >= 16 || senders[id].loaded) {
            return false;
        }
        bool loaded = tryLoadPublicKey(publicKeyFilename, senders[id].publicKey);
        senders[id].loaded = loaded;
        return loaded;
    }
    bool tryDecrypt(std::vector<u_char> & payload, u_char & senderId) {
        int ciphertextSize = payload.size() - crypto_box_NONCEBYTES - 1;
        if (ciphertextSize <= 0) {
            return false;
        }
        senderId = payload.back();
        if (senderId >= 16) {
            return false;
        }
        int result =
            crypto_box_open_easy(
                payload.data(), payload.data(),
                ciphertextSize, payload.data() + ciphertextSize,
                senders[senderId].publicKey.publicKey, recipientKeypair.secretKey);
        if (result == -1) {
            return false;
        }
        payload.resize(ciphertextSize - crypto_box_MACBYTES);
        return true;
    }
};

struct CryptoSecretBox {
    u_char key[crypto_secretbox_KEYBYTES];
    uint64_t nonce;
    u_char clientId;
    CryptoSecretBox(u_char clientId):clientId(clientId),nonce(0) {
        if (clientId >= 16) {
            throw std::runtime_error("invalid clientId");
        }
        crypto_secretbox_keygen(key);
    }
    CryptoSecretBox(u_char clientId, const void * keyBytes):clientId(clientId),nonce(0) {
        if (clientId >= 16) {
            throw std::runtime_error("invalid clientId");
        }
        memcpy(key, keyBytes, crypto_secretbox_KEYBYTES);
    }
    bool tryEncrypt(std::vector<u_char> & payload) {
        size_t messageSize = payload.size();
        u_char nonceBytes[crypto_secretbox_NONCEBYTES] = {};
        memcpy(nonceBytes, (void *)&nonce, sizeof(uint64_t));
        payload.resize(payload.size() + crypto_secretbox_MACBYTES);
        if (-1 == crypto_secretbox_easy(payload.data(), payload.data(), messageSize, nonceBytes, key)) {
            std::cout << "failed to encrypt payload: payload unmodified\n";
            payload.resize(messageSize);
            return false;
        }
        return true;
    }
    void appendNonceAndId(std::vector<u_char> & payload) {
        size_t payloadSize = payload.size();
        payload.resize(payloadSize + sizeof(nonce) + 1);
        memcpy(payload.data() + payloadSize, &nonce, sizeof(nonce));
        nonce++;
        payload.back() = clientId;
    }
    bool tryDecrypt(std::vector<u_char> & payload, u_char & clientId) {
        int payloadSize = payload.size() - sizeof(nonce) - 1;
        if (payloadSize <= 0) {
            std::cout << "payload is too small to be decrypted: payload unmodified\n";
            return false;
        }
        u_char nonceBytes[crypto_secretbox_NONCEBYTES] = {};
        memcpy(nonceBytes, payload.data() + payloadSize, sizeof(nonce));
        clientId = payload.back();
        if (clientId >= 16) {
            std::cout << "invalid clientId found in packet: payload unmodified\n";
            return false;
        }
        int result = crypto_secretbox_open_easy(payload.data(), payload.data(), payloadSize, nonceBytes, key);
        if (-1 == result) {
            std::cout << "failed to decrypt payload: payload unmodified\n";
            return false;
        }
        payload.resize(payloadSize - crypto_secretbox_MACBYTES);
        return true;
    }
};

struct UdpSocket {
    int sockfd;
    UdpSocket(int port) {
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd == -1) {
            throw std::runtime_error("Error creating socket");
        }
        sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);
        if (::bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Error binding socket");
        }
    }
    ~UdpSocket() {
        close(sockfd);
    }
    size_t recv(std::vector<u_char> & bytes, sockaddr_in & in) {
        bytes.resize(65535);
        socklen_t sender_len = sizeof(sockaddr_in);
        ssize_t recv_len = recvfrom(
            sockfd,
            bytes.data(),
            bytes.size() - 1,
            0,
            (sockaddr*)&in,
            &sender_len);

        return recv_len;
    }
    size_t recv(std::vector<u_char> & bytes) {
        sockaddr_in in;
        return recv(bytes, in);
    }
    bool trySend(const std::vector<u_char> & bytes, const sockaddr_in & sender_addr) {
        ssize_t sendResult = sendto(
            sockfd,
            bytes.data(),
            bytes.size(),
            0,
            (sockaddr*)&sender_addr,
            sizeof(sender_addr));

        if (sendResult == -1) return false;
        return true;
    }
};

void printHelp() {
    std::cout <<
R"(udpbox: <command>
available commands:
help: show this text
generate: generate a new public and private key
serve <port>: listen for clients on given port
connect: connect to a server
test: run tests and exit
)";}

FILE * openNewFile(const char * filename) {
    FILE * newfile = fopen(filename, "wx");
    if (!newfile) {
        std::cout << "generate: "<< filename << " file already exists.\n" ;
    }
    return newfile;
}

void generateKeys() {
    if (sodium_init() < 0) {
        std::cout << "error initializing libsodium\n";
        return;
    }
    FILE * publicfile = openNewFile("public.key");
    FILE * secretfile = openNewFile("secret.key");
    if (!publicfile || !secretfile) {
        if (publicfile) fclose(publicfile);
        if (secretfile) fclose(secretfile);
        std::cout << "For safety, no new keys were generated.\n";
        return;
    }
    CryptoBoxKeypair keypair;
    crypto_box_keypair(keypair.publicKey, keypair.secretKey);
    fwrite(keypair.publicKey, sizeof(keypair.publicKey), 1, publicfile);
    fwrite(keypair.secretKey, sizeof(keypair.secretKey), 1, secretfile);
    fclose(publicfile);
    fclose(secretfile);
    std::cout << "public.key generated: You can share this.\n";
    std::cout << "secret.key generated: No one should ever ask for this, and you should keep it secret.\n";
}

void serve(int port) {
    CryptoBoxRecipient recipient;
    if (!recipient.tryAddSender(0, "client.key")) {
        std::cout << "failed to add known sender\n";
        throw std::runtime_error("failed to add known sender");
    }

    if (sodium_init() < 0) {
        throw std::runtime_error("error initializing libsodium");
    }
    UdpSocket socket(port);
    std::vector<u_char> payload(5000);
    std::cout << "echoing udp on port " << port << '\n';
    bool done = false;
    while (!done) {
        sockaddr_in in;
        ssize_t length = socket.recv(payload, in);
        if (length > 0) {
            std::cout << "recieved " << length << " byte packet\n";
            payload.resize(length);
            u_char senderId;
            if (recipient.tryDecrypt(payload, senderId)) {
                std::cout << "decrypted " << payload.size() << " byte message from clientId " << senderId << std::endl;
            } else {
                std::cout << "failed to decrypt payload" << std::endl;
            }
        }
    }
}

void connect() {
    if (sodium_init() < 0) {
        throw std::runtime_error("error initializing libsodium");
    }
    CryptoBoxSender cryptoSender("server.key", 0);
    const char * message = "hello?";
    std::vector<u_char> payload(strlen(message));
    memcpy(payload.data(), message, strlen(message));

    std::cout << "sending " << payload.size() << " byte message to server\n";
    cryptoSender.encrypt(payload);
    cryptoSender.appendNonceAndId(payload);
    std::cout << "sending " << payload.size() << " byte encrypted payload to server\n";

    UdpSocket socket(22412);
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(44321);
    address.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (!socket.trySend(payload, address)) {
        throw std::runtime_error("failed to send on socket");
    }
}

void assert(bool result, const char * message) {
    if (!result) {
        throw std::runtime_error(message);
    }
}

void test() {
    try {
        CryptoSecretBox sender(4);
        CryptoSecretBox recipient(4, sender.key);

        const char * message = "test!";
        std::vector<u_char> payload(strlen(message));
        strcpy((char*)payload.data(), message);
        std::vector<u_char> originalPayload(payload);

        u_char clientId = 255;

        assert(sender.tryEncrypt(payload), "encrypt");
        sender.appendNonceAndId(payload);
        assert(recipient.tryDecrypt(payload, clientId), "decrypt");
        assert(clientId == 4, "clientId retrieved");
        assert(originalPayload.size() == payload.size(), "payload size match");
        assert(0 == memcmp(originalPayload.data(), payload.data(), originalPayload.size()), "payload match");
        assert(sender.nonce == 1, "nonce increment");
    } catch (std::runtime_error & e) {
        std::cout << "assertion failed: " << e.what() << std::endl;
        return;
    }
    std::cout << "no tests failed" << std::endl;
}

int main(int argc, char ** argv) {
    if (argc < 2) {
        printHelp();
        return 0;
    }
    std::string verb(argv[1]);
    if (verb == "help") {
        printHelp();
        return 0;
    } else if (verb == "generate") {
        generateKeys();
        return 0;
    } else if (verb == "connect") {
        connect();
    } else if (verb == "test") {
        test();
    } else if (verb == "serve") {
        if (argc < 3) {
            printHelp();
            return 0;
        } else {
            int port = atoi(argv[2]);
            if (port == -1) {
                printHelp();
                return 0;
            }
            serve(port);
        }
    }

    return 0;
}