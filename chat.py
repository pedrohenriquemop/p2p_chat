import argparse
import struct
import socket
from enum import Enum
from typing import List, Literal, Tuple
import threading
import time

PORT = 51511


class Utils:
    @staticmethod
    def get_message_type_from_code(code: int) -> str:
        try:
            return MessageCode(code).name
        except ValueError:
            raise ValueError(f"Unknown message code: {code}")


class MessageCode(Enum):
    PEER_REQUEST = 0x1
    PEER_RESPONSE = 0x2
    ARCHIVE_REQUEST = 0x3
    ARCHIVE_RESPONSE = 0x4

    def __str__(self):
        return str(self.value)


class RequestType:
    Literal[MessageCode.PEER_REQUEST, MessageCode.ARCHIVE_REQUEST]


class ResponseType:
    Literal[MessageCode.PEER_RESPONSE, MessageCode.ARCHIVE_RESPONSE]


class Chat:
    def __init__(self, size: int, message: str, rand: bytes, md5_hash: bytes):
        if size > 255:
            raise ValueError("Size must be less than or equal to 255")

        if len(message) != size:
            raise ValueError("Message length does not match size")

        if len(rand) != 16:
            raise ValueError("Random value must be 16 bytes long")

        if len(md5_hash) != 16:
            raise ValueError("Hash value must be 16 bytes long")

        self.size = size
        self.message = message
        self.rand = rand
        self.md5_hash = md5_hash

    def pack(self) -> bytes:
        message_bytes = self.message.encode("ascii")
        return struct.pack(
            f"!B{self.size}s16s16s", self.size, message_bytes, self.rand, self.md5_hash
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 37:
            raise ValueError("Data too short for Chat unpacking")

        size = data[0]
        message, rand, md5_hash = struct.unpack(f"!{size}s16s16s", data[1 : 33 + size])
        message = message.decode("ascii")

        return cls(size, message, rand, md5_hash)


class Request:
    def __init__(self, code: RequestType):
        self.code = code
        self.type = code.name

    def pack(self):
        return struct.pack("!B", self.code.value)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 1 or len(data) > 1:
            raise ValueError("Invalid data size for Request unpacking")

        code = RequestType(data[0])
        return cls(code)


class Response:
    def __init__(
        self, code: ResponseType, chat_amount: int = 0, chats: List[Chat] = []
    ):
        self.code = code
        self.type = code.name

        if chat_amount != len(chats):
            raise ValueError("chat_amount does not match the number of chats provided")

        self.chat_amount = chat_amount
        self.chats = chats

    def pack(self):
        return struct.pack("!BI", self.code.value) + b"".join(
            chat.pack() for chat in self.chats
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 1 or len(data) > 1:
            raise ValueError("Invalid data size for Request unpacking")

        code = RequestType(data[0])
        return cls(code)


class P2PChatEngine:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

        self.sock = None
        self.lock = threading.Lock()
        self.server_thread = None
        self.sender_thread = None
        self.active_connections = {}

    def start(self):
        print(f"Starting P2P Chat Engine on {self.ip}:{self.port}")

        addrinfo = socket.getaddrinfo(
            self.ip, self.port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        family, socktype, proto, canonname, sa = addrinfo[0]
        self.sock = socket.socket(family, socktype, proto)
        self.sock.settimeout(1.0)
        self.sock.bind(sa)
        self.sock.listen(5)  # max pending connections

        self.server_thread = threading.Thread(
            target=self.__connections_handler, daemon=True
        )
        self.server_thread.start()

        self.sender_thread = threading.Thread(target=self.__sender, daemon=True)
        self.sender_thread.start()

        self.__start_cli()

    def __connections_handler(self):
        print("Listening for incoming connections...")

        while True:
            try:
                conn, addr = self.sock.accept()
                print(f"Accepted connection from {addr}")

                with self.lock:
                    self.active_connections[addr] = conn

                listener_thread = threading.Thread(
                    target=self.__listener, args=(conn, addr), daemon=True
                )
                listener_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                print(f"Error accepting connection: {e}")

    def __listener(self, conn_sock: socket, addr: Tuple[str, int]):
        try:
            while True:
                header_byte = conn_sock.recv(1)

                print(f"Received byte: {header_byte[0]}")
                message_type = Utils.get_message_type_from_code(header_byte[0])
                print(f"Message type: {message_type}")
        except Exception as e:
            print(f"Error in listener for {addr}: {e}")
        finally:
            conn_sock.close()
            if addr in self.active_connections:
                del self.active_connections[addr]

    def __sender(self):
        while True:
            with self.lock:
                try:
                    if self.active_connections:
                        for peer_addr, peer_conn in self.active_connections.items():
                            try:
                                request = Request(MessageCode.PEER_REQUEST)
                                peer_conn.sendall(request.pack())
                                print(f"Sent {request.type} to {peer_addr}")
                            except Exception as e:
                                print(f"Error sending to {peer_addr}: {e}")
                except Exception as e:
                    print(f"Error in sender: {e}")
            time.sleep(10)

    def connect_to_peer(self, peer_ip: str):
        if not peer_ip:
            raise ValueError("Peer IP cannot be empty")

        if peer_ip == self.ip:
            raise Exception("Cannot connect to self")

        try:
            print(f"Connecting to peer: {peer_ip}:{PORT}")
            peer_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_sock.connect((peer_ip, PORT))
            print(f"Connected to {peer_ip}:{PORT}")
            self.active_connections[(peer_ip, PORT)] = peer_sock

            threading.Thread(
                target=self.__listener, args=(peer_sock, (peer_ip, PORT)), daemon=True
            ).start()
            return True
        except Exception as e:
            print(f"Could not connect to peer {peer_ip}:{PORT}: {e}")
            return False

    def __start_cli(self):
        accepted_connects = ["connect", "conn", "con", "c"]

        command = input()

        while command.lower() != "exit":
            try:
                command = command.lower().strip()
                start = command.split(" ")[0]
                if start in accepted_connects:
                    peer_ip = command.split(" ")[1]
                    self.connect_to_peer(peer_ip)
                else:
                    print(
                        f"Unknown command. Use '[{', '.join(accepted_connects)}] <ip>' to connect to a peer."
                    )

                command = input()
            except KeyboardInterrupt:
                print("\nExiting CLI...")
                self.sock.close()
                break
            except Exception as e:
                print(f"Error: {e}")
                command = input()


def main():
    parser = argparse.ArgumentParser(description="DCC Internet P2P Blockchain Chat CLI")

    parser.add_argument("ip", help="IP address of self.")

    args = parser.parse_args()

    ip = args.ip

    engine = P2PChatEngine(ip, PORT)

    engine.start()

    print("Program terminated.")


if __name__ == "__main__":
    main()
