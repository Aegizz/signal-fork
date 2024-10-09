/*
 * Copyright (c) 2014, Peter Thorson. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the WebSocket++ Project nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL PETER THORSON BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// **NOTE:** This file is based on the WebSocket++ utility client tutorial.

#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>

#include "client/websocket_endpoint.h"
#include "client/websocket_metadata.h"

#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>

#include <cstdlib>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <nlohmann/json.hpp> // For JSON library


#include "client/client_list.h" // Self made client list implementation
#include "client/aes_encrypt.h" // AES GCM Encryption with OpenSSL
#include "client/client_key_gen.h" // OpenSSL Key generation
#include "client/client_utilities.h" // For sending messages, checking connections
#include "client/Fingerprint.h" // For fingerprint generation

// Used to differentiate client processses locally
const int ClientNumber = 1;

// Create key file names
std::string privFileName = "client/private_key" + std::to_string(ClientNumber) + ".pem";
std::string pubFileName = "client/public_key" + std::to_string(ClientNumber) + ".pem";

// Define keys
EVP_PKEY* privKey;
EVP_PKEY* pubKey;

//Global pointer for client list
ClientList* global_client_list = new ClientList;

std::ostream & operator<< (std::ostream & out, connection_metadata const & data) {
    out << "> URI: " << data.m_uri << "\n"
        << "> Status: " << data.m_status << "\n"
        << "> Remote Server: " << (data.m_server.empty() ? "None Specified" : data.m_server) << "\n"
        << "> Error/close reason: " << (data.m_error_reason.empty() ? "N/A" : data.m_error_reason) << "\n";

    return out;
}

int main() {
    int numConnections=0;
    // Load keys
    privKey = Client_Key_Gen::loadPrivateKey(privFileName.c_str());
    pubKey = Client_Key_Gen::loadPublicKey(pubFileName.c_str());

    // If keys files don't exist, create keys and load from newly created files
    if(!privKey || !pubKey){
        std::cout << "\nCreating key files\n" << std::endl;
        if(!Client_Key_Gen::key_gen(ClientNumber)){
            privKey = Client_Key_Gen::loadPrivateKey(privFileName.c_str());
            pubKey = Client_Key_Gen::loadPublicKey(pubFileName.c_str());
        }else{
            std::cout << "Could not load keys" << std::endl;
            return 1;
        }
    }

    bool done = false;
    std::string input;
    std::string fingerprint = Fingerprint::generateFingerprint(pubKey);
    websocket_endpoint endpoint(fingerprint, privKey);
    int currentID=-1;

    while (!done) {
        // Print all clients, labelling this client as "You". Fingerprint is used to obtain server_id and client_id of this user.
        std::pair<int, std::pair<int, std::string>> myInfo = global_client_list->retrieveClientFromFingerprint(fingerprint);
        if(myInfo.first != -1){
            global_client_list->printUsers(myInfo.first, myInfo.second.first);
        }

        std::cout << "Enter Command: ";
        std::getline(std::cin, input);

        if (input == "quit") { // Quit program
            endpoint.close(currentID, websocketpp::close::status::normal, "Client logging off");
            done = true;
        } else if (input == "help") { // Display command help
            std::cout
                << "\nCommand List:\n"
                << "connect\n"
                << "send <message type>\n"
                << "close [<close code:default=1000>]\n"
                << "show\n"
                << "help: Display this help text\n"
                << "quit: Exit the program\n"
                << std::endl;
        } else if (input == "connect") { // If connect was entered
            if(numConnections > 0){
                std::cout << "You cannot connect to more than one server" << std::endl;
                continue;
            }

            bool validUri=false;
            // Keep looping until a valid URI has been entered
            while(!validUri){
                std::cout << "Enter server uri: " << std::endl;
                std::string uri;
                std::getline(std::cin, uri);  // Get the uri from the user
                
                // If the uri entered is greater than 5 characters (should improve this to proper uri input validation)
                if((int)uri.size() > 5){
                    // If the first 5 letters are "ws://"
                    if(uri.substr(0,5) == "ws://"){
                        validUri=true;
                        // Attempt to connect to uri
                        currentID = endpoint.connect(uri, global_client_list);
                        if (currentID != -1) {
                            std::cout << "> Initiated connection to " << uri << std::endl;

                            // Obtain metadata
                            connection_metadata::ptr metadata = endpoint.get_metadata(currentID);

                            // Do not continue until websocket has finished connecting
                            while(metadata->get_status() == "Connecting"){
                                metadata = endpoint.get_metadata(currentID);
                            }
 
                            if(metadata->get_status() == "Failed"){ // If the connection failed exit loop
                                std::cout << "Connection Failed to " << uri << std::endl;
                                continue;
                            }else if(metadata->get_status() == "Open"){ // If the connection succeeded send confirmation messages
                                std::cout << "> Established connection with " << uri << std::endl;
                                numConnections++;

                                // Send hello message
                                ClientUtilities::send_hello_message(&endpoint, currentID, privKey, pubKey, 12345);

                                // Send client list request
                                ClientUtilities::send_client_list_request(&endpoint, currentID);
                            }
                        }
                    }else{ // If uri is not prefixed by "ws://" it is an invalid uri
                        std::cout << "Not a valid URI" << std::endl;
                        continue;
                    }
                }else{ // If uri less than 5 chaacters it is not long enough and re-prompt user
                    std::cout << "Uri not long enough" << std::endl;
                    continue;
                }
            }
        } else if (input == "close") { // If close was entered
            std::stringstream ss(input);
            
            std::string cmd;
            int close_code = websocketpp::close::status::normal;
            std::string reason = "Client logging off";
            
            ss >> cmd >> close_code;

            // Check the close code
            if (close_code < 1000 && close_code > 3999) {
                std::cout << "> Invalid close code: " << close_code << std::endl;
                continue;
            }

            endpoint.close(currentID, close_code, reason);

            numConnections--;
        }  else if (input == "show") { // If show was entered
            
            // Obtain metadata and print it
            connection_metadata::ptr metadata = endpoint.get_metadata(currentID);
            if (metadata) {
                std::cout << *metadata << std::endl;
            } else {
                std::cout << "> No connection established" << std::endl;
            }
        } else if (input.substr(0,4) == "send") { // If send was entered
            // If no message type followed the send command tell user it was used incorrectly
            if((int)input.size() == 4){
                std::cout << "> Incorrect usage of command 'send <message type>'" << std::endl;
            }else{
                std::stringstream ss(input);
                std::string cmd;
                std::string msgType;

                // Extract command and message type from input
                ss >> cmd >> msgType;

                // Get metadata of the connection
                connection_metadata::ptr metadata = endpoint.get_metadata(currentID);

                // If metadata could be obtained
                if (metadata) {
                    // Prompt user for a message
                    std::cout << "Enter message to send: " << std::endl;
                    std::string message;
                    std::getline(std::cin, message);  // Get the message from the user

                    // Check message type entered is valid
                    bool validType=false;
                    while(!validType){
                        if (msgType == "private"){ // If the message type is private
                            validType=true;

                            bool clientsEntered = false;

                            // Declare vectors for recipients
                            std::vector<EVP_PKEY*> list_public_keys;
                            std::vector<std::string> destination_servers;
                            std::vector<std::string> public_keys_strings;

                            // Loop to continue querying for clients
                            while (!clientsEntered) {
                                // Get Server ID
                                std::cout << "Enter the Client's Server ID. If done entering client's type \"done\" or type cancel if you don't want to continue sending a message." << std::endl;
                                std::string serverString="";
                                int serverInt=-1;
                                std::getline(std::cin, serverString);
                                if(serverString == "done"){ // Clients have been provided
                                    if((int)list_public_keys.size() == 0){ // No clients have been provided
                                        std::cout << "No clients provided. You need to specify clients." << std::endl;
                                        continue;
                                    }else{ // Clients have been provided, send the chat
                                        ClientUtilities::send_chat(&endpoint, currentID, message, privKey, pubKey, list_public_keys, destination_servers, 12345);  //send to server
                                        break;
                                    }
                                }else if(serverString == "cancel"){ // Cancel message
                                    validType=true;
                                    clientsEntered=true;
                                    continue;
                                }

                                // Try to convert entered serverID to an integer, and re-prompt if invalid
                                try {
                                    serverInt = std::stoi(serverString);
                                } catch (const std::invalid_argument& e) {
                                    std::cout << "Invalid argument: " << serverString << " is not a valid Server ID." << std::endl;
                                    continue;
                                }
                                
                                //Get Client ID
                                std::cout << "Enter the Client ID: If done entering client's type \"done\" or type cancel if you don't want to continue sending a message. " << std::endl;
                                std::string clientString="";
                                int clientInt=-1;
                                std::getline(std::cin, clientString);
                                if(clientString == "done"){ // Clients have been provided
                                    if((int)list_public_keys.size() == 0){ // No clients have been provided
                                        std::cout << "No clients provided. You need to specify clients." << std::endl;
                                        continue;
                                    }else{ // Clients have been provided, send the chat
                                        ClientUtilities::send_chat(&endpoint, currentID, message, privKey, pubKey, list_public_keys, destination_servers, 12345);  //send to server
                                        break;
                                    }
                                }else if(clientString == "cancel"){ // Cancel message
                                    validType=true;
                                    clientsEntered=true;
                                    continue;
                                }
                                
                                // Try to convert entered clientID to an integer, and re-prompt if invalid
                                try {
                                    clientInt = std::stoi(clientString);
                                } catch (const std::invalid_argument& e) {
                                    std::cout << "Invalid argument: " << clientString << " is not a valid Client ID." << std::endl;
                                    continue;
                                }
                                
                                // Retrieve <client_id, public_key> from serverID and clientID
                                std::pair<int, std::string> retClient = global_client_list->retrieveClient(serverInt, clientInt);
                                // If no public key was found, the client doesn't exist in the list
                                if(retClient.second == ""){
                                    continue;
                                }
                                std::string public_key = retClient.second;

                                // Check if the client is already a recipient in the message
                                if(std::find(public_keys_strings.begin(), public_keys_strings.end(), public_key) != public_keys_strings.end()){
                                    std::cout << "Client " << clientInt << " on Server " << serverInt << " is already a recipient" << std::endl;
                                    continue;
                                }
                                
                                // Compare fingerprint to this user's fingerprint to determine if the user is trying to send a message to themselves
                                std::string genFingerprint = Fingerprint::generateFingerprint(Client_Key_Gen::stringToPEM(public_key));
                                if(fingerprint == genFingerprint){
                                    std::cout << "You cannot be a recipient of your own message" << std::endl;
                                    continue;
                                }

                                // Push keys to vectors and obtain destination server using serverID and push to vector
                                public_keys_strings.push_back(public_key);
                                destination_servers.push_back(global_client_list->retrieveAddress(serverInt));
                                list_public_keys.push_back(Client_Key_Gen::stringToPEM(public_key));

                                // Check whether user has finished selecting their clients
                                bool validYesNo = false;
                                while(!validYesNo) {
                                    std::cout << "Are you finished adding all the clients you want to send the message to? (Yes/No): " << std::endl;
                                    std::string yes_or_no;
                                    std::getline(std::cin, yes_or_no);

                                    // Convert input to uppercase to handle case-insensitivity
                                    for (auto &c : yes_or_no) {
                                        c = std::toupper(c);
                                    }
                                    
                                    if (yes_or_no == "YES") { // If the user is finished adding clients, send the message
                                        validYesNo = true;
                                        clientsEntered = true;

                                        ClientUtilities::send_chat(&endpoint, currentID, message, privKey, pubKey, list_public_keys, destination_servers, 12345);  //send to server
                                    } else if (yes_or_no == "NO") { // Continue prompting for clients
                                        std::cout << "Ok, let's add more clients" << std::endl;
                                        validYesNo = true;
                                    } else { // Prompt for an answer to Are you finished adding all the clients you want to send the message to?
                                        std::cout << "Input Invalid: Must be either YES or NO." << std::endl;
                                        continue;
                                    }
                                }
                            }
        
                        } else if(msgType == "public"){ // If the message type is public
                            validType=true;

                            // Send the public chat
                            ClientUtilities::send_public_chat(&endpoint, currentID, message, privKey, pubKey, 12345);
                        }else{ // An invalid message type was entered, re-prompt the user.
                            std::cout << "Invalid message type entered\nValid types are \"private\" and \"public\"" << std::endl;
                            break;
                        }   
                    }
                } else {
                    std::cout << "> No connection established" << std::endl;
                }
            }
        } else {
            std::cout << "> Unrecognized Command" << std::endl;
        }
    }

    return 0;
}
