#ifndef WEBSOCKET_METADATA_H
#define WEBSOCKET_METADATA_H

#include <vector>

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <nlohmann/json.hpp> // For JSON library
#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>
//Self made client list implementation
#include "client_list.h"
//Self mage AES GCM Encryption with OpenSSL
#include "aes_encrypt.h"
#include "client.h"
#include "hexToBytes.h"
#include "client_signature.h"
#include "client_key_gen.h"
#include "signed_data.h"

class websocket_endpoint;

class connection_metadata {
private:
    ClientList * global_client_list;
public:
    typedef websocketpp::lib::shared_ptr<connection_metadata> ptr;

    connection_metadata(int id, websocketpp::connection_hdl hdl, std::string uri, ClientList * client_list_pointer)
      : m_id(id)
      , m_hdl(hdl)
      , m_status("Connecting")
      , m_uri(uri)
      , m_server("N/A")
    {
        global_client_list = client_list_pointer;
    }

    void on_open(client * c, websocketpp::connection_hdl hdl) {
        m_status = "Open";

        client::connection_ptr con = c->get_con_from_hdl(hdl);
        m_server = con->get_response_header("Server");
    }

    void on_fail(client * c, websocketpp::connection_hdl hdl) {
        m_status = "Failed";

        client::connection_ptr con = c->get_con_from_hdl(hdl);
        m_server = con->get_response_header("Server");
        m_error_reason = con->get_ec().message();
    }
    
    void on_close(client * c, websocketpp::connection_hdl hdl) {
        m_status = "Closed";
        client::connection_ptr con = c->get_con_from_hdl(hdl);
        std::stringstream s;
        s << "close code: " << con->get_remote_close_code() << " (" 
          << websocketpp::close::status::get_string(con->get_remote_close_code()) 
          << "), close reason: " << con->get_remote_close_reason();
        m_error_reason = s.str();
        std::cout << s.str() << std::endl;
    }

    void on_message(client* c, websocketpp::connection_hdl hdl, client::message_ptr msg, std::string fingerprint, EVP_PKEY* privateKey) {
        // Vulnerable code: the payload without validation
        std::string payload = msg->get_payload();

        // Deserialize JSON message
        nlohmann::json messageJSON = nlohmann::json::parse(payload);
        std::string dataString;
        nlohmann::json data;

        if(messageJSON.contains("data")){
            dataString = messageJSON["data"].get<std::string>();
            data = nlohmann::json::parse(dataString);
        }

        if(messageJSON["type"] == "client_list"){
            std::cout << "\nClient list received" << std::endl;

            global_client_list->update(messageJSON);
            std::cout << "\n";

            std::pair<int, std::pair<int, std::string>> myInfo = global_client_list->retrieveClientFromFingerprint(fingerprint);
            if(myInfo.first != -1){
                global_client_list->printUsers(myInfo.first, myInfo.second.first);
            }
        }else if(data["type"] == "public_chat"){
            std::pair<int, std::pair<int, std::string>> chatInfo = global_client_list->retrieveClientFromFingerprint(data["sender"]);
            if(chatInfo.first == -1){
                std::cout << "Invalid fingerprint received in public message" << std::endl;
                return;
            }

            int server_id = chatInfo.first;
            int client_id = chatInfo.second.first;
            std::string public_key = chatInfo.second.second;
            EVP_PKEY* pubKey = Client_Key_Gen::stringToPEM(public_key);

            std::string signature = messageJSON["signature"];
            int counter = messageJSON["counter"];

            if(!ClientSignature::verifySignature(signature, data.dump() + std::to_string(counter), pubKey)){
                std::cout << "Invalid signature" << std::endl;
                return;
            }
            std::cout << "Verified signature" << std::endl;

            std::cout << "Public chat received from client " << client_id << " on server " << server_id << std::endl;
            std::cout << data["message"] << std::endl;
        }else if(data["type"] == "chat"){
            std::string decrypted_str = SignedData::decryptSignedMessage(messageJSON.dump(), privateKey);

            if(decrypted_str == ""){
                return;
            }

            try {
                // Attempt to parse the string as JSON
                nlohmann::json chat = nlohmann::json::parse(decrypted_str);
                
                // Convert participants to a std::vector<std::string>
                std::vector<std::string> participants = chat["participants"].get<std::vector<std::string>>();

                // If parsing is successful, you can work with the JSON object
                std::pair<int, std::pair<int, std::string>> chatInfo = global_client_list->retrieveClientFromFingerprint(participants[0]);
                if(chatInfo.first == -1){
                    std::cout<<"Invalid fingerprint received in message"<<std::endl;
                    return;
                }

                int server_id = chatInfo.first;
                int client_id = chatInfo.second.first;
                std::string public_key = chatInfo.second.second;
                EVP_PKEY* pubKey = Client_Key_Gen::stringToPEM(public_key);

                std::string signature = messageJSON["signature"];
                int counter = messageJSON["counter"];

                if(!ClientSignature::verifySignature(signature, data.dump() + std::to_string(counter), pubKey)){
                    std::cout << "Invalid signature" << std::endl;
                    return;
                }
                std::cout << "Verified signature\n" << std::endl;

                std::cout << "Chat received from client " << client_id << " on server " << server_id << std::endl << std::endl;
                std::cout << chat["message"] << "\n" << std::endl;
                std::cout << "All recipients:" << std::endl;
                for(int i=1; i<(int)participants.size(); i++){
                    std::pair<int, std::pair<int, std::string>> chatInfo = global_client_list->retrieveClientFromFingerprint(participants[i]);
                    if(chatInfo.first == -1){
                        std::cout<<"Invalid recipient fingerprint received in message"<<std::endl;
                        continue;
                    }
                    server_id = chatInfo.first;
                    client_id = chatInfo.second.first;
                    std::cout << "ServerID: " << server_id << " ClientID: " << client_id << std::endl;
                }
            }catch (nlohmann::json::parse_error& e) {
                // Catch parse error exception and display error message
                std::cerr << "Decrypted message is an Invalid JSON format: " << e.what() << std::endl;
            }

            /*
            // Decode cipher text and IV from Base64 into hex, then convert from hex to bytes
            std::string ciphertextHex = Base64::decode(data["chat"]);
            std::string ciphertextString = hexToBytesString(ciphertextHex);
            std::string ivHex = Base64::decode(data["iv"]);
            std::string ivString = hexToBytesString(ivHex);
            
            // Get tag by taking last 16 (specified by AES_GCM_TAG_SIZE) characters of ciphertext in byte form
            std::string tagString = ciphertextString.substr(ciphertextString.length() - AES_GCM_TAG_SIZE);
            // Remove tag from cipher text string to leave actual ciphertext
            ciphertextString = ciphertextString.substr(0, ciphertextString.length() - AES_GCM_TAG_SIZE);

            std::vector<std::string> symm_keys = data["symm_keys"].get<std::vector<std::string>>();

            // For each recipient
            for(size_t i=0;i<symm_keys.size();i++){
                // Decode the encrypted symmetric key from Base64 into hex and cast to unsigned char*
                std::string symm_key_hex = Base64::decode(symm_keys.at(i));
                const unsigned char* symm_key_hex_pointer = reinterpret_cast<const unsigned char *>(symm_key_hex.c_str());

                // Decrypt using recipients RSA private key
                unsigned char* decryptedKey = nullptr;
                size_t decryptedKeyLen = (size_t)Client_Key_Gen::rsaDecrypt(privateKey, symm_key_hex_pointer, symm_key_hex.size(), &decryptedKey);

                // Convert produced decrypted unsigned char* to string 
                std::string keyStringHex;
                for(int i=0; i<(int)decryptedKeyLen; i++){
                    keyStringHex.push_back(decryptedKey[i]);
                }
                
                // Convert hex to bytes and convert to unsigned char vector to be used in AES-GCM decryption
                std::string keyString = hexToBytesString(keyStringHex);
                std::vector<unsigned char> key(keyString.begin(), keyString.end());

                // Check if key is the right size
                if (keyString.size() != AES_GCM_KEY_SIZE) {
                    std::cerr << "Decryption of the symmetric key failed!" << std::endl;
                    OPENSSL_free(decryptedKey);
                    continue;
                }
                
                OPENSSL_free(decryptedKey); // Free allocated memory after use

                // Free allocated memory after use
                std::vector<unsigned char> ciphertext(ciphertextString.begin(), ciphertextString.end());
                std::vector<unsigned char> iv(ivString.begin(), ivString.end());
                std::vector<unsigned char> tag(tagString.begin(), tagString.end());
                std::vector<unsigned char> decrypted_text;

                // Decrypt using AES-GCM and handle any errors
                if (AESGCM::aes_gcm_decrypt(ciphertext, key, iv, tag, decrypted_text)) {
                    std::string decrypted_str(decrypted_text.begin(), decrypted_text.end());

                    try {
                        // Attempt to parse the string as JSON
                        nlohmann::json chat = nlohmann::json::parse(decrypted_str);

                        // If parsing is successful, you can work with the JSON object
                        std::pair<int, std::pair<int, std::string>> chatInfo = global_client_list->retrieveClientFromFingerprint(chat["participants"][0]);
                        if(chatInfo.first == -1){
                            std::cout<<"Invalid fingerprint received in message"<<std::endl;
                            return;
                        }

                        int server_id = chatInfo.first;
                        int client_id = chatInfo.second.first;
                        std::string public_key = chatInfo.second.second;
                        EVP_PKEY* pubKey = Client_Key_Gen::stringToPEM(public_key);

                        std::string signature = messageJSON["signature"];
                        int counter = messageJSON["counter"];

                        if(!ClientSignature::verifySignature(signature, data.dump() + std::to_string(counter), pubKey)){
                            std::cout << "Invalid signature" << std::endl;
                            return;
                        }
                        std::cout << "Verified signature" << std::endl;

                        std::cout << "Chat received from client " << client_id << " on server " << server_id << std::endl << std::endl;
                        std::cout << chat["message"] << std::endl;
                        break;
                    }catch (nlohmann::json::parse_error& e) {
                        // Catch parse error exception and display error message
                        std::cerr << "Invalid JSON format: " << e.what() << std::endl;
                        continue;
                    }
                } else {
                    std::cerr << "Decryption failed!" << std::endl;
                    return;
                }
            }

            */
            
        }else{
            // Print the received message
            std::cout << "> Invalid message type received: " << payload << std::endl;
        }
        std::cout << "\n";
    }

    websocketpp::connection_hdl get_hdl() const {
        return m_hdl;
    }
    
    int get_id() const {
        return m_id;
    }
    
    std::string get_status() const {
        return m_status;
    }

    friend std::ostream & operator<< (std::ostream & out, connection_metadata const & data);
private:
    int m_id;
    websocketpp::connection_hdl m_hdl;
    std::string m_status;
    std::string m_uri;
    std::string m_server;
    std::string m_error_reason;
};

#endif