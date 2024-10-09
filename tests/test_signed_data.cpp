#include <iostream>
#include <string>
#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include "../client/signed_data.h"  // Ensure this path is correct
#include "../client/client_list.h"
#include "../client/client.h"
#include "../client/client_key_gen.h"
#include "../client/websocket_endpoint.h"
#include "../client/websocket_metadata.h"
#include "../client/DataMessage.h"
#include "../client/Fingerprint.h"
#include "../client/client_utilities.h"

using websocketpp::connection_hdl;

typedef websocketpp::server<websocketpp::config::asio> server;

void testSendAndReceive(SignedData& signedData, EVP_PKEY* privateKey, std::vector<EVP_PKEY *> recipent_pub_keys, std::vector<std::string> server_addresses, websocket_endpoint* endpoint, int id) {
    // Sample data to send
    std::string data = DataMessage::generateDataMessage("Hello world!", recipent_pub_keys, server_addresses);
    int counter = 1;

    // Sending a signed message
    signedData.sendSignedMessage(data, privateKey, endpoint, id, counter);

    nlohmann::json message_json;

    message_json["type"] = "signed_data";
    message_json["data"] = data;
    message_json["counter"] = counter;
    message_json["signature"] = ClientSignature::generateSignature(data, privateKey, std::to_string(counter));

    std::string json_string = message_json.dump();

    // Create a mock signed message for testing decryption
    std::string mockMessageStr = message_json.dump();

    // Attempt to decrypt the signed message
    std::string decryptedMessage = signedData.decryptSignedMessage(mockMessageStr, privateKey);

    // Output the result
    if (!decryptedMessage.empty()) {
        std::cout << "Decrypted message: " << decryptedMessage << std::endl;
    } else {
        std::cout << "Decryption failed or returned empty." << std::endl;
    }
}

ClientList* global_client_list = new ClientList;

#include <unistd.h>  // For fork(), exec(), and kill()
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>  // For SIGTERM

int main() {
    // Load keys
    EVP_PKEY* privateKey = Client_Key_Gen::loadPrivateKey("tests/test-keys/private_key0.pem");
    EVP_PKEY* publicKey = Client_Key_Gen::loadPublicKey("tests/test-keys/public_key0.pem");
    if (!privateKey) {
        std::cerr << "Failed to load private key!" << std::endl;
        return 1; // Exit if key loading fails
    }
    if (!publicKey) {
        std::cerr << "Failed to load public key!" << std::endl;
        return 1;
    }

    // Generate fingerprints
    std::string fingerprint = Fingerprint::generateFingerprint(publicKey);

    // Start the server
    pid_t server_pid = fork();
    if (server_pid == 0) {
        // In the child process, replace it with the server executable
        execl("./server", "server", nullptr);
        // If execl returns, an error occurred
        std::cerr << "Failed to start server!" << std::endl;
        return 1;
    } else if (server_pid < 0) {
        std::cerr << "Fork failed!" << std::endl;
        return 1;
    }

    // Give the server a moment to start
    sleep(1);  // Adjust the duration as necessary

    // Initialize WebSocket server (or endpoint) here
    websocket_endpoint endpoint(fingerprint, privateKey);
    
    // Mock connection metadata
    int id = endpoint.connect("ws://localhost:9002", global_client_list); // Example connection ID

    // Wait for client to connect to server
    sleep(1);

    // Send hello message to confirm connection
    ClientUtilities::send_hello_message(&endpoint, id, privateKey, publicKey, 1);

    // Create an instance of SignedData
    SignedData signedData;

    // Test sending and receiving messages
    testSendAndReceive(signedData, privateKey, std::vector<EVP_PKEY*>({publicKey}), std::vector<std::string>({"ws://localhost:9002"}), &endpoint, id);

    // Clean up resources (if needed)
    EVP_PKEY_free(privateKey); // Free the private key when done

    // Terminate the server after client operations
    kill(server_pid, SIGTERM);  // Send termination signal to the server
    waitpid(server_pid, nullptr, 0);

    return 0;
}
