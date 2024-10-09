#include "client_signature.h"
#include "client_key_gen.h"
#include "Sha256Hash.h"
#include "base64.h"
#include "hexToBytes.h"

/*Generates a signature from a message based on a client's private key. Will concatenate counter for you does not need to be included*/
std::string ClientSignature::generateSignature(std::string message, EVP_PKEY *private_key, std::string counter) {
    // Combine the message and counter, then hash the result
    std::string combinedString = message + counter;
    std::string hashed_stringHex = Sha256Hash::hashStringSha256(combinedString);
    std::string hashedStringBytes = hexToBytesString(hashed_stringHex);
    // Prepare the buffer for encryption
    unsigned char *encrypted = nullptr; // Single pointer to hold encrypted data
    const unsigned char *combinedMessage = reinterpret_cast<const unsigned char*>(hashedStringBytes.c_str());
    // Encrypt the hashed string using rsaEncrypt
    int encrypted_length = Client_Key_Gen::rsaSign(private_key, combinedMessage, hashedStringBytes.length(), &encrypted);

    // If encryption failed, return an empty string (or handle the error accordingly)
    if (encrypted_length <= 0 || encrypted == nullptr) {
        std::cerr << "Encryption failed." << std::endl;
        return "";
    }

    // Convert the encrypted data to a std::string
    std::string rsa_string(reinterpret_cast<char*>(encrypted), encrypted_length);

    // Base64 encode the encrypted string to create the signature
    std::string base64signature = Base64::encode(rsa_string);

    // Free the encrypted buffer after use
    OPENSSL_free(encrypted);

    return base64signature;
}


/* Verifies an encrypted signature against a decrypted message, provided the original message decoded and the encrypted string still Base64 encoded.*/
bool ClientSignature::verifySignature(std::string encrypted_signature, std::string decrypted_message, EVP_PKEY* publicKey){
    std::string decoded_signature = Base64::decode(encrypted_signature);
    const unsigned char *combinedMessage = reinterpret_cast<const unsigned char*>(decoded_signature.c_str());
    std::string hashed_message = Sha256Hash::hashStringSha256(decrypted_message);
    const unsigned char *hashed = reinterpret_cast<const unsigned char*>(hashed_message.c_str());

    int verify = Client_Key_Gen::rsaVerify(publicKey, hashed, hashed_message.length(), combinedMessage, decoded_signature.length());

    return (verify);
}
