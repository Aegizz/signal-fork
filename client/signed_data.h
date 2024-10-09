#ifndef SIGNED_DATA_H
#define SIGNED_DATA_H
#include <string>
#include <vector>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>
#include "client_signature.h"
#include "client_key_gen.h"
#include "base64.h"
#include "hexToBytes.h"

class websocket_endpoint;

class SignedData{
    public:
        /* 
            Will send a signed message over the specified endpoint and id 
            Calls generateSignature and websocketpp functions.
            Assumes the data provided is already encrypted.
        */
        void static sendSignedMessage(std::string data, EVP_PKEY * private_key, websocket_endpoint* endpoint, int id, int counter);
        /* 
            Iterates over a signed message and attempts to decrypt the aes key with it's own private key
            Returns the decrypted message.
            Function to decrypt a signed messsage's content, does not verify the reciever or check counter
            Ensure the entire message is provided.
         */
        std::string static decryptSignedMessage(std::string data, EVP_PKEY * private_key);
};
#endif