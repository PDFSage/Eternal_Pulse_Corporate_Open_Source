# Eternal_Pulse_Corporate_Open_Source

// aes_encrypt.cpp
//
// A simple AES-256-CBC file encryption utility using OpenSSL.
// Compile with: g++ aes_encrypt.cpp -o aes_encrypt -lcrypto
//
// Usage: aes_encrypt <64-hex-char-key> <input-file> <output-file>
//   - key must be 32 bytes (64 hex chars) for AES-256
//   - Generates a random 16-byte IV, prepends it to the output file, and encrypts
//     the plaintext from <input-file> into <output-file>.
//
// Note: OpenSSL headers are required. On Debian/Ubuntu:
//   apt-get install libssl-dev
//
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>

void encrypt_file(const std::string &infile,
                  const std::string &outfile,
                  const std::vector<unsigned char> &key,
                  const std::vector<unsigned char> &iv)
{
    std::ifstream fin(infile, std::ios::binary);
    if (!fin) {
        std::cerr << "[ERROR] Cannot open input file: " << infile << "\n";
        std::exit(1);
    }
    std::ofstream fout(outfile, std::ios::binary);
    if (!fout) {
        std::cerr << "[ERROR] Cannot open output file: " << outfile << "\n";
        std::exit(1);
    }

    // Write the IV at the beginning of the output file
    fout.write(reinterpret_cast<const char *>(iv.data()), iv.size());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "[ERROR] EVP_CIPHER_CTX_new() failed\n";
        std::exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) {
        std::cerr << "[ERROR] EVP_EncryptInit_ex() failed\n";
        EVP_CIPHER_CTX_free(ctx);
        std::exit(1);
    }

    const size_t BUFSIZE = 4096;
    std::vector<unsigned char> buffer(BUFSIZE);
    std::vector<unsigned char> outbuf(BUFSIZE + AES_BLOCK_SIZE);
    int outlen = 0;

    while (fin.good()) {
        fin.read(reinterpret_cast<char *>(buffer.data()), BUFSIZE);
        std::streamsize readBytes = fin.gcount();
        if (readBytes > 0) {
            if (1 != EVP_EncryptUpdate(ctx,
                                       outbuf.data(),
                                       &outlen,
                                       buffer.data(),
                                       static_cast<int>(readBytes)))
            {
                std::cerr << "[ERROR] EVP_EncryptUpdate() failed\n";
                EVP_CIPHER_CTX_free(ctx);
                std::exit(1);
            }
            fout.write(reinterpret_cast<const char *>(outbuf.data()), outlen);
        }
    }

    if (1 != EVP_EncryptFinal_ex(ctx, outbuf.data(), &outlen)) {
        std::cerr << "[ERROR] EVP_EncryptFinal_ex() failed\n";
        EVP_CIPHER_CTX_free(ctx);
        std::exit(1);
    }
    fout.write(reinterpret_cast<const char *>(outbuf.data()), outlen);

    EVP_CIPHER_CTX_free(ctx);
    fin.close();
    fout.close();
    std::cout << "[+] Encrypted \"" << infile << "\" -> \"" << outfile << "\"\n";
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <64-hex-key> <input-file> <output-file>\n";
        return 1;
    }
    std::string keyhex = argv[1];
    std::string infile = argv[2];
    std::string outfile = argv[3];

    if (keyhex.size() != 64) {
        std::cerr << "[ERROR] Key must be exactly 64 hex characters (32 bytes).\n";
        return 1;
    }

    std::vector<unsigned char> key(32);
    for (int i = 0; i < 32; i++) {
        std::string byteHex = keyhex.substr(2 * i, 2);
        char *endptr = nullptr;
        long val = std::strtol(byteHex.c_str(), &endptr, 16);
        if (endptr == byteHex.c_str() || val < 0 || val > 0xFF) {
            std::cerr << "[ERROR] Invalid hex character in key: " << byteHex << "\n";
            return 1;
        }
        key[i] = static_cast<unsigned char>(val);
    }

    // Generate random IV (16 bytes for AES-128/192/256 CBC)
    std::vector<unsigned char> iv(AES_BLOCK_SIZE);
    if (1 != RAND_bytes(iv.data(), AES_BLOCK_SIZE)) {
        std::cerr << "[ERROR] RAND_bytes() failed to generate IV\n";
        return 1;
    }

    encrypt_file(infile, outfile, key, iv);
    return 0;
}
