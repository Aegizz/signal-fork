#include "client_key_gen.h"

void Client_Key_Gen::handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int Client_Key_Gen::key_gen(int client_id, bool test, bool clientTests){
    std::string idString = std::to_string(client_id);

    std::string privFilename = "client/private_key" + idString + ".pem";
    std::string pubFilename = "client/public_key" + idString + ".pem";

    if(test){
        privFilename = "tests/private_key" + idString + ".pem";
        pubFilename = "tests/public_key" + idString + ".pem";
    }

    if(clientTests){
        privFilename = "tests/test-keys/private_key" + idString + ".pem";
        pubFilename = "tests/test-keys/public_key" + idString + ".pem";
    }

    // 1. Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // 2. Create RSA key generation context
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) handleErrors();

    // 3. Generate RSA private key (2048 bits)
    if (EVP_PKEY_keygen_init(ctx) <= 0) handleErrors();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) handleErrors();
    
    // 4. Set public exponent to 65537 (must use BIGNUM for the exponent)
    BIGNUM *e = BN_new();
    if (!e || !BN_set_word(e, RSA_F4)) {  // RSA_F4 is 65537
        std::cerr << "Error setting public exponent\n";
        handleErrors();
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e) <= 0) handleErrors();
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) handleErrors();

    // 4. Write the private key to private_key.pem (PEM format)
    FILE *private_key_file = fopen(privFilename.c_str(), "wb");
    if (!private_key_file) {
        std::cerr << "Unable to open private_key.pem for writing\n";
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    if (!PEM_write_PrivateKey(private_key_file, pkey, NULL, NULL, 0, NULL, NULL)) {
        std::cerr << "Error writing private key\n";
        handleErrors();
    }
    fclose(private_key_file);

    // 5. Write the public key to public_key.pem (SPKI format, PEM)
    FILE *public_key_file = fopen(pubFilename.c_str(), "wb");
    if (!public_key_file) {
        std::cerr << "Unable to open public_key.pem for writing\n";
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return 1;
    }
    if (!PEM_write_PUBKEY(public_key_file, pkey)) {
        std::cerr << "Error writing public key\n";
        handleErrors();
    }
    fclose(public_key_file);

    // Clean up
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    // 6. Cleanup OpenSSL
    EVP_cleanup();
    ERR_free_strings();

    //std::cout << "Private key and public key (SPKI format) have been saved successfully." << std::endl;
    
    return 0;
}


EVP_PKEY* Client_Key_Gen::loadPrivateKey(const char* filename) {
    FILE* keyFile = fopen(filename, "rb");
    if (!keyFile) {
        std::cerr << "Unable to open private key file." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    if (!pkey) {
        std::cerr << "Error reading private key." << std::endl;
        handleErrors();
    }
    return pkey;
}

// Function to read a PEM-encoded public key from a file
EVP_PKEY* Client_Key_Gen::loadPublicKey(const char* filename) {
    FILE* keyFile = fopen(filename, "rb");
    if (!keyFile) {
        std::cerr << "Unable to open public key file." << std::endl;
        return nullptr;
    }
    EVP_PKEY* pkey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
    fclose(keyFile);
    if (!pkey) {
        std::cerr << "Error reading public key." << std::endl;
        handleErrors();
    }
    return pkey;
}

// Function to encrypt data using the public key
int Client_Key_Gen::rsaEncrypt(EVP_PKEY* pubKey, const unsigned char* plaintext, size_t plaintext_len, unsigned char** encrypted) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_encrypt_init(ctx) <= 0) handleErrors();

    // Set the padding to RSA-OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();

    // Set the OAEP hash function to SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) handleErrors();

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) handleErrors();  // Ensure MGF1 is SHA-256

    // Determine buffer length for the encrypted data
    size_t encrypted_len;
    if (EVP_PKEY_encrypt(ctx, NULL, &encrypted_len, plaintext, plaintext_len) <= 0) handleErrors();

    *encrypted = (unsigned char*)OPENSSL_malloc(encrypted_len);
    if (*encrypted == NULL) handleErrors();

    // Encrypt the data
    if (EVP_PKEY_encrypt(ctx, *encrypted, &encrypted_len, plaintext, plaintext_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return encrypted_len;  // Return length of the encrypted data
}

// Function to decrypt data using the private key
int Client_Key_Gen::rsaDecrypt(EVP_PKEY* privKey, const unsigned char* encrypted, size_t encrypted_len, unsigned char** decrypted) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx) handleErrors();

    if (EVP_PKEY_decrypt_init(ctx) <= 0) handleErrors();

    // Set the padding to RSA-OAEP
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) handleErrors();

    // Set the OAEP hash function to SHA-256
    if (EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha256()) <= 0) handleErrors();

    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) handleErrors();  // Ensure MGF1 is SHA-256

    // Determine buffer length for the decrypted data
    size_t decrypted_len;
    if (EVP_PKEY_decrypt(ctx, NULL, &decrypted_len, encrypted, encrypted_len) <= 0) handleErrors();

    *decrypted = (unsigned char*)OPENSSL_malloc(decrypted_len);
    if (*decrypted == NULL) handleErrors();

    // Zero the allocated buffer
    memset(*decrypted, 0, decrypted_len);

    // Decrypt the data
    if (EVP_PKEY_decrypt(ctx, *decrypted, &decrypted_len, encrypted, encrypted_len) <= 0) {
        // If decryption fails, check the error code
        /*unsigned long err_code = ERR_get_error();
        if (err_code) {
            char err_buf[120];
            ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
            std::cerr << "Decryption failed: " << err_buf << std::endl;
        }*/
        EVP_PKEY_CTX_free(ctx);
        return -1;  // Return -1 to indicate decryption failure
    }

    EVP_PKEY_CTX_free(ctx);
    return decrypted_len;  // Return length of the decrypted data
}
// Function to sign data using the private key
int Client_Key_Gen::rsaSign(EVP_PKEY* privKey, const unsigned char* data, size_t data_len, unsigned char** signature) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKey, NULL);
    if (!ctx) handleErrors();

    // Initialize signing context
    if (EVP_PKEY_sign_init(ctx) <= 0) handleErrors();

    // Set the padding scheme to RSA-PSS
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) handleErrors();

    // Set the hash algorithm for the PSS scheme (SHA-256 in this case)
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) handleErrors();

    // Set the MGF1 (Mask Generation Function) to SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) handleErrors();

    // Set the salt length
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 32) <= 0) handleErrors();

    // Determine the buffer length for the signature
    size_t signature_len;
    if (EVP_PKEY_sign(ctx, NULL, &signature_len, data, data_len) <= 0) handleErrors();

    *signature = (unsigned char*)OPENSSL_malloc(signature_len);
    if (*signature == NULL) handleErrors();

    // Sign the data
    if (EVP_PKEY_sign(ctx, *signature, &signature_len, data, data_len) <= 0) handleErrors();

    EVP_PKEY_CTX_free(ctx);
    return signature_len;  // Return length of the signature
}
// Function to verify the signature using the public key
int Client_Key_Gen::rsaVerify(EVP_PKEY* pubKey, const unsigned char* data, size_t data_len, const unsigned char* signature, size_t signature_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubKey, NULL);
    if (!ctx) handleErrors();

    // Initialize verification context
    if (EVP_PKEY_verify_init(ctx) <= 0) handleErrors();
    
    // Set the padding scheme to RSA-PSS
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PSS_PADDING) <= 0) handleErrors();

    // Set the hash algorithm for the PSS scheme (SHA-256)
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0) handleErrors();

    // Set the MGF1 (Mask Generation Function) to SHA-256
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha256()) <= 0) handleErrors();

    // Set the salt length
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, 32) <= 0) handleErrors();

    // Verify the signature
    int result = EVP_PKEY_verify(ctx, signature, signature_len, data, data_len);
    
    EVP_PKEY_CTX_free(ctx);
    return result;  // Returns 1 for success, 0 for failure
}

EVP_PKEY* Client_Key_Gen::stringToPEM(std::string pKey) {
    BIO* bio = BIO_new_mem_buf(pKey.data(), -1);  // Create a BIO for the key string
    //BIO* bio = BIO_new_mem_buf(found_server->second.data(), -1);  // Create a BIO for the key string
    if (!bio) Client_Key_Gen::handleErrors(); // Must be fully qualified call to avoid compiler errors

    EVP_PKEY* clientPKey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);  // Read PEM public key
    BIO_free(bio);  // Free the BIO after use

    if (!clientPKey) {
        std::cerr << "Error loading public key from string." << std::endl;
        Client_Key_Gen::handleErrors(); // Must be fully qualified call to avoid compiler errors
    }

    return clientPKey;
}
