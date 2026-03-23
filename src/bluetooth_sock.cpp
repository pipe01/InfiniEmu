#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <thread>
#include <cstring>
#include <functional>

using namespace std::placeholders;

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#include "bluetooth.hpp"
#include "bluetooth/ble_packets.hpp"

using uuid128 = std::array<uint8_t, 128 / 8>;

class Connection
{
public:
    Connection(bluetooth_t *bt, int socket) : bt(bt), socket(socket) {}

    void send_json(const json &msg)
    {
        std::string str = msg.dump();
        send(socket, str.c_str(), str.size(), 0);
    }

    std::optional<uint16_t> uuid_to_handle(json char_json)
    {
        if (char_json.is_number())
        {
            uint16_t want_uuid = char_json;

            for (auto uuid = bt->attrs16.begin(); uuid != bt->attrs16.end(); ++uuid)
            {
                if (want_uuid == uuid->second)
                {
                    return uuid->first;
                }
            }
        }
        else if (char_json.is_array())
        {
            uuid128 want_uuid = char_json;

            for (auto uuid = bt->attrs128.begin(); uuid != bt->attrs128.end(); ++uuid)
            {
                if (want_uuid == uuid->second)
                {
                    return uuid->first;
                }
            }
        }

        return std::nullopt;
    }

    std::optional<std::variant<uint16_t, uuid128>> handle_to_uuid(uint16_t handle)
    {
        for (auto uuid = bt->attrs16.begin(); uuid != bt->attrs16.end(); ++uuid)
        {
            if (handle == uuid->first)
            {
                return uuid->second;
            }
        }
        for (auto uuid = bt->attrs128.begin(); uuid != bt->attrs128.end(); ++uuid)
        {
            if (handle == uuid->first)
            {
                return uuid->second;
            }
        }

        return std::nullopt;
    }

    void handle_message(json &msg)
    {
        if (!msg["type"].is_string())
            return;

        std::string msg_type = msg["type"];

        if (msg_type == "connect")
        {
            bt->Connect();
        }
        else if (msg_type == "disconnect")
        {
            bt->Disconnect();
        }
        else if (msg_type == "list_attrs")
        {
            json resp;
            resp["type"] = "response";

            json attrs = json::array();

            for (auto uuid = bt->attrs16.begin(); uuid != bt->attrs16.end(); ++uuid)
            {
                json attr = json::object();
                attr["handle"] = uuid->first;
                attr["uuid16"] = uuid->second;
                attrs.push_back(attr);
            }
            for (auto uuid = bt->attrs128.begin(); uuid != bt->attrs128.end(); ++uuid)
            {
                json attr = json::object();
                attr["handle"] = uuid->first;
                attr["uuid128"] = uuid->second;
                attrs.push_back(attr);
            }

            resp["attributes"] = attrs;

            send_json(resp);
        }
        else if (msg_type == "read_attr")
        {
            uint16_t handle = msg["handle"];

            size_t timeout = msg.contains("timeout") ? (size_t)msg["timeout"] : 2000;

            if (!bt->EnqueueReadRequest(handle, std::bind(&Connection::read_callback, this, _1, _2), timeout))
            {
                send_json({
                    {"type", "error"},
                    {"error", "not ready yet"},
                });
            }
        }
        else if (msg_type == "write_attr")
        {
            uint16_t handle = msg["handle"];
            any_bytes value = msg["value"];

            size_t timeout = msg.contains("timeout") ? (size_t)msg["timeout"] : 2000;

            if (!bt->EnqueueWriteRequest(handle, value, std::bind(&Connection::write_callback, this, _1), timeout))
            {
                send_json({
                    {"type", "error"},
                    {"error", "not ready yet"},
                });
            }
        }
        else if (msg_type == "ready?")
        {
            send_json({
                {"type", "response"},
                {"ready", bt->GetStage() == Stage::DONE},
            });
        }
    }

    void handle_notify(uint16_t handle, any_bytes value)
    {
        send_json({
            {"type", "notify"},
            {"handle", handle},
            {"value", value},
        });
    }

private:
    bluetooth_t *bt;
    int socket;

    void read_callback(int error, any_bytes data)
    {
        if (error != 0)
        {
            send_json({
                {"type", "error_response"},
                {"error_code", error},
            });
        }
        else
        {
            send_json({
                {"type", "response"},
                {"data", data},
            });
        }
    }

    void write_callback(int error)
    {
        if (error != 0)
        {
            send_json({
                {"type", "error_response"},
                {"error_code", error},
            });
        }
        else
        {
            send_json({{"type", "response"}});
        }
    }
};

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
        Connection conn(bt, clientSocket);

        bt->notify_callback = std::bind(&Connection::handle_notify, conn, _1, _2);

        int n;
        while ((n = recv(clientSocket, buffer, sizeof(buffer), 0)) > 0)
        {
            json msg = json::parse(buffer, buffer + n, nullptr, false);
            if (!msg.is_discarded())
            {
                conn.handle_message(msg);
            }
        }

        bt->notify_callback.reset();

        close(clientSocket);
    }
}

extern "C" void bluetooth_sock_start(bluetooth_t *bt)
{
    std::thread t(run_loop, bt);
    t.detach();
}
