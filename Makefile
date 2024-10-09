# Define the compiler
CXX = g++

# Define compiler flags
CXXFLAGS = -Wall -std=c++11

# Define the libraries
LIBS = -lssl -lcrypto -pthread

CLIENT_FILES=client/*.cpp
SERVER_FILES=server-files/*.cpp client/Sha256Hash.cpp client/base64.cpp client/hexToBytes.cpp
# Targets

all: userClient userClient2 server server2 server3 testClient testClient2 testClient3 test-client
#all: userClient userClient2 server server2 server3 test-client

test: debug-all server server2 client testClient test.sh test-client-list test-client-aes-encrypt test-client-sha256 test-client-key-gen test-base64 test-client-signature test-client-signed-data test-hello-message test-chat-message test-data-message test-message-generator
	echo "Running tests..."
	chmod +x test.sh
	bash test.sh
	echo "Running client tests..."
	./test-client-list
	./test-client-aes-encrypt
	./test-client-sha256
	./test-client-key-gen
	./test-base64
	./test-client-signature
#	./test-client-signed-data
	./test-chat-message
	./test-data-message
	./test-hello-message
	./test-message-generator

userClient: userClient.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLIENT_FILES) $(LIBS)
userClient2: userClient2.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLIENT_FILES) $(LIBS)
userClient3: userClient3.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLIENT_FILES) $(LIBS)

# For testing 
testClient: testClient.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLIENT_FILES) $(LIBS)
testClient2: testClient2.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLIENT_FILES) $(LIBS) 
testClient3: testClient3.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(CLIENT_FILES) $(LIBS) 
server: server.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(SERVER_FILES) $(LIBS) -lz
server2: server2.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(SERVER_FILES) $(LIBS) -lz
server3: server3.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(SERVER_FILES) $(LIBS) -lz

userClients: userClient userClient2 userClient3
testClients: testClient testClient2 testClient3
servers: server server2 server3

# Clean up build artifacts
clean:
	rm -f userClient userClient2 userClient3 server server2 server3 client-debug server-debug testClient testClient2 testClient3 tests/server.log tests/client.log debugClient test-client-sha256 test-client-aes-encrypt test-client-list test-base64 test-client-key-gen test-client-signature test-client-chat-message test-client-data-message test-client-signed-data userClient userClient-debug test-chat-message test-hello-message test-data-message test-fingerprint test-message-generator

debug-all: userClient-debug testClient server-debug

userClient-debug: userClient.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(CLIENT_FILES) $(LIBS) -lz -fno-stack-protector

server-debug: server.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS) $(SERVER_FILES) -lz -fno-stack-protector

test-client: test-client-list test-client-aes-encrypt test-client-sha256 test-base64 test-client-key-gen test-client-signature test-client-signed-data test-chat-message test-data-message test-hello-messsage

test-client-list: tests/test_client_list.cpp client/*.cpp client/Fingerprint.h
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-client-aes-encrypt: tests/test_aes_encrypt.cpp client/aes_encrypt.cpp client/aes_encrypt.h
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-client-sha256: tests/test_Sha256Hash.cpp client/Sha256Hash.cpp client/Sha256Hash.h
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-client-key-gen: tests/test_client_key_gen.cpp client/client_key_gen.h client/client_key_gen.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-base64: tests/test_base64.cpp client/base64.cpp
	$(CXX) $(CXXFLAGSR) -g -o $@ $^ $(LIBS)
test-client-signature: client/base64.cpp client/client_key_gen.cpp client/client_signature.cpp tests/test_client_signature.cpp client/Sha256Hash.cpp client/hexToBytes.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-client-signed-data: client/*.cpp client/Fingerprint.h tests/test_signed_data.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-data-message: client/aes_encrypt.cpp client/client_key_gen.cpp client/base64.cpp tests/test_data_message.cpp client/hexToBytes.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-chat-message: client/aes_encrypt.cpp client/client_key_gen.cpp client/base64.cpp tests/test_chat_message.cpp client/hexToBytes.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-hello-message: client/client_key_gen.cpp tests/test_hello_message.cpp client/hexToBytes.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-fingerprint: tests/test_fingerprint.cpp client/client_key_gen.cpp client/base64.cpp client/Sha256Hash.cpp client/hexToBytes.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-public-chat-message: tests/test_public_chat_message.cpp client/client_key_gen.cpp client/base64.cpp client/Sha256Hash.cpp client/hexToBytes.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS)
test-message-generator: tests/test_message_generator.cpp
	$(CXX) $(CXXFLAGS) -g -o $@ $^ $(LIBS) $(CLIENT_FILES)