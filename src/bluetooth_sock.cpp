#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <thread>
#include <cstring>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "bluetooth.hpp"
#include "bluetooth/ble_packets.hpp"

static void send_json(int socket, const json &msg)
{
    std::string str = msg.dump();
    send(socket, str.c_str(), str.size(), 0);
}

static void handle_message(bluetooth_t *bt, int socket, json &msg)
{
    std::string msg_type = msg["type"];

    if (msg_type == "connect")
    {
        bt->Connect();
    }
    else if (msg_type == "disconnect")
    {
        bt->Disconnect();
    }
    else if (msg_type == "list_chars")
    {
        json resp;
        json uuids16 = json::array();
        json uuids128 = json::array();

        for (auto uuid = bt->attrs16.begin(); uuid != bt->attrs16.end(); ++uuid)
        {
            uuids16.push_back(uuid->second);
        }
        for (auto uuid = bt->attrs128.begin(); uuid != bt->attrs128.end(); ++uuid)
        {
            uuids128.push_back(uuid->second);
        }

        resp["uuids16"] = uuids16;
        resp["uuids128"] = uuids128;

        send_json(socket, resp);
    }
    else if (msg_type == "read_char")
    {
        json char_json = msg["uuid"];

        uint16_t handle = 0;
        bool found = false;

        if (char_json.is_number())
        {
            uint16_t want_uuid = char_json;

            for (auto uuid = bt->attrs16.begin(); uuid != bt->attrs16.end(); ++uuid)
            {
                if (want_uuid == uuid->second)
                {
                    handle = uuid->first;
                    found = true;
                }
            }
        }
        else if (char_json.is_array())
        {
            std::array<uint8_t, 128 / 8> want_uuid = char_json;

            for (auto uuid = bt->attrs128.begin(); uuid != bt->attrs128.end(); ++uuid)
            {
                if (want_uuid == uuid->second)
                {
                    handle = uuid->first;
                    found = true;
                }
            }
        }

        if (!found)
        {
            send_json(socket, {
                                  {"type", "error"},
                                  {"error", "invalid uuid"},
                              });
            return;
        }

        read_callback cb = [socket](int error, any_bytes data)
        {
            if (error != 0)
            {
                send_json(socket, {
                                      {"type", "error_response"},
                                      {"error_code", error},
                                  });
            }
            else
            {
                send_json(socket, {
                                      {"type", "response"},
                                      {"data", data},
                                  });
            }
        };

        size_t timeout = msg.contains("timeout") ? (size_t)msg["timeout"] : 2000;

        if (!bt->EnqueueReadRequest(handle, cb, timeout))
        {
            send_json(socket, {
                                  {"type", "error"},
                                  {"error", "not ready yet"},
                              });
        }
    }
}

static void run_loop(bluetooth_t *bt)
{
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        perror("Failed to open socket");
        return;
    }

    int yes = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(9345);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0)
    {
        perror("Failed to bind socket");
        return;
    }

    if (listen(serverSocket, 5) < 0)
    {
        perror("Failed to listen on socket");
        return;
    }

    char buffer[4096];

    while (true)
    {
        int clientSocket = accept(serverSocket, nullptr, nullptr);

        int n;
        while ((n = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0)
        {
            json msg = json::parse(buffer, nullptr, false);
            if (!msg.is_discarded())
            {
                handle_message(bt, clientSocket, msg);
            }
        }

        close(clientSocket);
    }
}

extern "C" void bluetooth_sock_start(bluetooth_t *bt)
{
    std::thread t(run_loop, bt);
    t.detach();
}
