#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/dh.h>
#include <string.h>

#define AES_KEYLEN 32  // 256-bit AES key
#define NONCE_LEN 16   // 128-bit nonce for randomness

// Error handling for OpenSSL functions
void handleErrors() {
    ERR_print_errors_fp(stderr);  // Print OpenSSL error messages
    abort();  // Abort the program
}

// Generate random bytes for nonce/salt
void generate_random_bytes(unsigned char *buf, int len) {
    if (!RAND_bytes(buf, len)) {
        handleErrors();
    }
}

// Generate a Diffie-Hellman key pair using the same parameters
EVP_PKEY *generate_dh_keypair(EVP_PKEY *params) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(params, NULL);

    if (!kctx) {
        printf("Error: Failed to create PKEY context for keygen\n");
        handleErrors();
    }

    if (EVP_PKEY_keygen_init(kctx) <= 0) {
        printf("Error: Failed to initialize DH keygen\n");
        handleErrors();
    }

    if (EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        printf("Error: Failed to generate DH keypair\n");
        handleErrors();
    }

    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

// Derive shared secret between two Diffie-Hellman keys
unsigned char *derive_shared_secret(EVP_PKEY *private_key, EVP_PKEY *peer_key, size_t *secret_size) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, NULL);
    if (!ctx) {
        printf("Error: Failed to create context for key derivation\n");
        handleErrors();
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        printf("Error: Failed to initialize key derivation\n");
        handleErrors();
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        printf("Error: Failed to set peer key\n");
        handleErrors();
    }

    // Determine the size of the shared secret
    if (EVP_PKEY_derive(ctx, NULL, secret_size) <= 0) {
        printf("Error: Failed to determine shared secret size\n");
        handleErrors();
    }

    // Allocate buffer for shared secret
    unsigned char *shared_secret = malloc(*secret_size);
    if (!shared_secret || EVP_PKEY_derive(ctx, shared_secret, secret_size) <= 0) {
        printf("Error: Failed to derive shared secret\n");
        handleErrors();
    }

    EVP_PKEY_CTX_free(ctx);
    return shared_secret;
}

// AES encryption function
int encrypt_aes(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int ciphertext_len;

    if (!ctx) {
        printf("Error: Failed to create encryption context\n");
        handleErrors();
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
        printf("Error: Failed to initialize AES encryption\n");
        handleErrors();
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) {
        printf("Error: Failed to update AES encryption\n");
        handleErrors();
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) <= 0) {
        printf("Error: Failed to finalize AES encryption\n");
        handleErrors();
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES decryption function
int decrypt_aes(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    if (!ctx) {
        printf("Error: Failed to create decryption context\n");
        handleErrors();
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) <= 0) {
        printf("Error: Failed to initialize AES decryption\n");
        handleErrors();
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) {
        printf("Error: Failed to update AES decryption\n");
        handleErrors();
    }
    plaintext_len = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        printf("Error: Failed to finalize AES decryption\n");
        handleErrors();
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// Key Evolution Function
void evolve_key(unsigned char *key, int key_len, unsigned char *salt) {
    for (int i = 0; i < key_len; i++) {
        key[i] ^= salt[i % NONCE_LEN];  // Use salt to evolve the key
    }
}

int main() {
    // Step 1: Generate Diffie-Hellman parameters (prime length: 2048)
    EVP_PKEY *params = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx) {
        printf("Error: Failed to create context for DH paramgen\n");
        handleErrors();
    }

    if (EVP_PKEY_paramgen_init(pctx) <= 0) {
        printf("Error: Failed to initialize DH paramgen\n");
        handleErrors();
    }

    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048) <= 0) {
        printf("Error: Failed to set DH prime length\n");
        handleErrors();
    }

    if (EVP_PKEY_paramgen(pctx, &params) <= 0) {
        printf("Error: Failed to generate DH parameters\n");
        handleErrors();
    }

    EVP_PKEY_CTX_free(pctx);

    // Step 2: Generate Diffie-Hellman key pairs for Alice and Bob using the same parameters
    EVP_PKEY *alice_keypair = generate_dh_keypair(params);
    EVP_PKEY *bob_keypair = generate_dh_keypair(params);

    // Step 3: Derive shared secret for both parties
    size_t secret_size;
    unsigned char *alice_shared_secret = derive_shared_secret(alice_keypair, bob_keypair, &secret_size);
    unsigned char *bob_shared_secret = derive_shared_secret(bob_keypair, alice_keypair, &secret_size);

    // Step 4: AES Key and IV
    unsigned char aes_key[AES_KEYLEN];
    unsigned char iv[NONCE_LEN];
    memcpy(aes_key, alice_shared_secret, AES_KEYLEN);  // Use the shared secret for the key
    generate_random_bytes(iv, NONCE_LEN);  // Random IV for AES

    // Get user input for the plaintext message
    char plaintext[128];
    printf("Enter the message to encrypt: ");
    fgets(plaintext, sizeof(plaintext), stdin); // Read input from the user
    plaintext[strcspn(plaintext, "\n")] = '\0';  // Remove trailing newline

    // Step 5: Encrypt the message using AES
    unsigned char ciphertext[128];
    int ciphertext_len = encrypt_aes((unsigned char *)plaintext, strlen(plaintext), aes_key, iv, ciphertext);

    // Step 6: Decrypt the message using AES
    unsigned char decryptedtext[128];
    int decryptedtext_len = decrypt_aes(ciphertext, ciphertext_len, aes_key, iv, decryptedtext);
    decryptedtext[decryptedtext_len] = '\0';  // Null-terminate the decrypted text

    // Step 7: Evolve the AES key over time using salt
    unsigned char salt[NONCE_LEN];
    generate_random_bytes(salt, NONCE_LEN);
    evolve_key(aes_key, AES_KEYLEN, salt);

    // Step 8: Free resources
    EVP_PKEY_free(alice_keypair);
    EVP_PKEY_free(bob_keypair);
    EVP_PKEY_free(params);  // Free the shared DH parameters
    free(alice_shared_secret);
    free(bob_shared_secret);

    return 0;
}