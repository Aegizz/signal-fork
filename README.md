# Implementation of Olaf-Neighbourhood Protocol for Tutorial 7

- Code server in C++
- Code client in C++

We need to come to some consensus on what parameters to use.

Use a makefile for compiling.

Feel free to modify this code to implement your vulnerabilties. As far as I am aware we will need to code the frontend of our applications and agree on some methodology of communication.

```bash
sudo apt-get install libboost-all-dev && sudo apt-get install libssl-dev && sudo apt-get install zlib1g-dev

git submodule update --init

cd websocketpp

mkdir build

cd build

cmake ..

sudo make install

cd ..

cd ..

cd json

mkdir build

cd build

cmake ..

sudo make install
```
# Running the client-server

To compile the client-server use the following commands

```bash

make client

./client

make server

./server

```

To establish connection between client and server, run in client ```connect ws://localhost:9002```

Alternatively, compile debugClient using ```make test``` which automatically makes a connection (make sure server is running before debugClient)

# Current Implemented Features
- Client <-> Server communication with multiple clients able to connect
- Client sends hello message when connecting with public key (not implemented RSA yet)
- Client sends client list request
- Client generates UTC timestamp in ISO 8601 format for TTD in broadcasted packets
    - TTD not implemented
- Client can send message to server (no encryption yet)
- Server can process hello message from client
- Server can send client list to client

# Vulnerable Code

### Vulnerability #1
 In server.cpp, there is an insecure string copy which can cause a stack overflow, luckily it is protected by the compiler.... except that the developer disable stack protection and memory protection for debugging!!! Oh no!
    Insecure Copy /server.cpp Line 115
    server-debug Makefile Line 40

### Vulnerability #2
 In the gitignore, there is not ignorance of .pem files, the files used for key generation. This will likely lead to a user or users leaking keys at some point.
 This is a common way that users leak private information on the internet and has potential to cause issues later down the line as commit history cannot be removed.
### Vulnerability #3
 Oops! We forgot to discard messages from users where the signature does not match, the message will still be forwarded provided it can be decoded and will identify the user based on their client-id and server-id.