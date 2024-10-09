#include "client_utilities.h"

std::string ClientUtilities::get_ttd(){
    // Generate current time
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now();

    std::chrono::minutes minute(1);

    // Add one minute
    std::chrono::system_clock::time_point newTime = now + minute;

    std::time_t convTime = std::chrono::system_clock::to_time_t(newTime);

    // Convert to GMT time and time structure
    std::tm* utc_tm = std::gmtime(&convTime);

    // Convert to ISO 8601 structure
    std::stringstream timeString;
    timeString << std::put_time(utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    
    return timeString.str();
}

bool ClientUtilities::is_connection_open(websocket_endpoint* endpoint, int id){
    connection_metadata::ptr metadata = endpoint->get_metadata(id);

    // Do not continue until websocket has finished connecting
    if(metadata->get_status() == "Open"){
        return true;
    }
    return false;
}

void ClientUtilities::send_hello_message(websocket_endpoint* endpoint, int id, EVP_PKEY* privKey, EVP_PKEY* pubKey, int counter){
    std::string json_string = MessageGenerator::helloMessage(privKey, pubKey, counter);

    // Send the message via the connection
    if(!is_connection_open(endpoint, id)){
        return;
    }
    websocketpp::lib::error_code ec;
    endpoint->send(id, json_string, websocketpp::frame::opcode::text, ec);

    if (ec) {
        std::cout << "> Error sending hello message: " << ec.message() << std::endl;
    } else {
        std::cout << "> Hello message sent" << std::endl;
    }
}

void ClientUtilities::send_client_list_request(websocket_endpoint* endpoint, int id){
    std::string json_string = MessageGenerator::clientListRequestMessage();

    // Send the message via the connection
    if(!is_connection_open(endpoint, id)){
        return;
    }
    websocketpp::lib::error_code ec;
    endpoint->send(id, json_string, websocketpp::frame::opcode::text, ec);

    if (ec) {
        std::cout << "> Error sending client list request message: " << ec.message() << std::endl;
    } else {
        std::cout << "> Client list request sent" << "\n" << std::endl;
    }
}

void ClientUtilities::send_public_chat(websocket_endpoint* endpoint, int id, std::string message, EVP_PKEY* privKey, EVP_PKEY* pubKey, int counter){
    std::string json_string = MessageGenerator::publicChatMessage(message, privKey, pubKey, counter);

    // Send the message via the connection
    if(!is_connection_open(endpoint, id)){
        return;
    }
    websocketpp::lib::error_code ec;
    endpoint->send(id, json_string, websocketpp::frame::opcode::text, ec);

    if (ec) {
        std::cout << "> Error sending public chat message: " << ec.message() << std::endl;
    } else {
        std::cout << ">  Public chat message sent" << std::endl;
    }
}

void ClientUtilities::send_chat(websocket_endpoint* endpoint, int connection_id, std::string message, EVP_PKEY* privKey, EVP_PKEY* pubKey, std::vector<EVP_PKEY*> their_public_keys, std::vector<std::string> destination_servers_vector, int counter, int client_id, int server_id){
    std::string json_string = MessageGenerator::chatMessage(message, privKey, pubKey, their_public_keys, destination_servers_vector, counter, client_id, server_id);

    if(!is_connection_open(endpoint, connection_id)){
        return;
    }
    websocketpp::lib::error_code ec;
    endpoint->send(connection_id, json_string, websocketpp::frame::opcode::text, ec);

    if (ec) {
        std::cout << "> Error sending chat message: " << ec.message() << std::endl;
    } else {
        std::cout << ">  Chat message sent" <<  std::endl;
    }
}