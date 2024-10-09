#ifndef WEBSOCKET_ENDPOINT_H
#define WEBSOCKET_ENDPOINT_H
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
#include "websocket_metadata.h"

class SignedData;

class websocket_endpoint {
public:
    websocket_endpoint (std::string fingerprint, EVP_PKEY* privateKey) : m_next_id(0){
        m_fingerprint = fingerprint;
        m_privateKey = privateKey;

        m_endpoint.clear_access_channels(websocketpp::log::alevel::all);
        m_endpoint.clear_error_channels(websocketpp::log::elevel::all);

        m_endpoint.init_asio();
        m_endpoint.start_perpetual();

        m_thread.reset(new websocketpp::lib::thread(&client::run, &m_endpoint));
    }

    ~websocket_endpoint() {
        m_endpoint.stop_perpetual();

        /*for (con_list::const_iterator it = m_connection_list.begin(); it != m_connection_list.end(); ++it) {
            if (it->second->get_status() != "Open") {
                // Only close open connections
                continue;
            }
            
            std::cout << "> Closing connection " << it->second->get_id() << std::endl;
            
            websocketpp::lib::error_code ec;
            m_endpoint.close(it->second->get_hdl(), websocketpp::close::status::going_away, "", ec);
            if (ec) {
                std::cout << "> Error closing connection " << it->second->get_id() << ": "  
                          << ec.message() << std::endl;
            }
        }*/
        
        m_thread->join();
    }

    int connect(std::string const & uri, ClientList * global_client_list) {
        websocketpp::lib::error_code ec;

        client::connection_ptr con = m_endpoint.get_connection(uri, ec);

        if (ec) {
            std::cout << "> Connect initialization error: " << ec.message() << std::endl;
            return -1;
        }

        int new_id = m_next_id++;
        connection_metadata::ptr metadata_ptr(new connection_metadata(new_id, con->get_handle(), uri, global_client_list));
        m_connection_list[new_id] = metadata_ptr;

        con->set_open_handler(websocketpp::lib::bind(
            &connection_metadata::on_open,
            metadata_ptr,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ));
        con->set_fail_handler(websocketpp::lib::bind(
            &connection_metadata::on_fail,
            metadata_ptr,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ));
        con->set_close_handler(websocketpp::lib::bind(
            &connection_metadata::on_close,
            metadata_ptr,
            &m_endpoint,
            websocketpp::lib::placeholders::_1
        ));
        con->set_message_handler(websocketpp::lib::bind(
            &connection_metadata::on_message,
            metadata_ptr,
            &m_endpoint,
            websocketpp::lib::placeholders::_1,
            websocketpp::lib::placeholders::_2,
            m_fingerprint,
            m_privateKey
        ));

        m_endpoint.connect(con);

        return new_id;
    }
    void send(int id, const std::string& message, websocketpp::frame::opcode::value opcode, websocketpp::lib::error_code& ec) {
        // Get connection handle from connection id
        connection_metadata::ptr metadata = get_metadata(id);
        
        if (metadata) {
            m_endpoint.send(metadata->get_hdl(), message, opcode, ec);
        } else {
            ec = websocketpp::lib::error_code(websocketpp::error::invalid_state);  // Set error code if connection id is invalid
        }
    }

    void close(int id, websocketpp::close::status::value code, std::string reason) {
        websocketpp::lib::error_code ec;
        
        con_list::iterator metadata_it = m_connection_list.find(id);
        if (metadata_it == m_connection_list.end()) {
            std::cout << "> No connection found with id " << id << std::endl;
            return;
        }else if (metadata_it->second->get_status() != "Open") {
            // Only close open connections
            return;
        }
        
        m_endpoint.close(metadata_it->second->get_hdl(), code, reason, ec);
        if (ec) {
            std::cout << "> Error initiating close: " << ec.message() << std::endl;
        }else{
            // Remove connection from list
            m_connection_list.erase(id);
        }
    }

    connection_metadata::ptr get_metadata(int id) const {
        con_list::const_iterator metadata_it = m_connection_list.find(id);
        if (metadata_it == m_connection_list.end()) {
            return connection_metadata::ptr();
        } else {
            return metadata_it->second;
        }
    }
private:
    typedef std::map<int,connection_metadata::ptr> con_list;

    client m_endpoint;
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;

    con_list m_connection_list;
    int m_next_id;
    std::string m_fingerprint;
    EVP_PKEY* m_privateKey;
};
#endif