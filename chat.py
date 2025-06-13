import argparse
import struct
import socket
from enum import Enum
from typing import List, Literal, Tuple
import threading
import time

PORT = 51511
HASH_LENGTH = 16
PEER_REQUEST_INTERVAL = 5


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

        if len(rand) != HASH_LENGTH:
            raise ValueError(f"Random value must be {HASH_LENGTH} bytes long")

        if len(md5_hash) != HASH_LENGTH:
            raise ValueError(f"Hash value must be {HASH_LENGTH} bytes long")

        self.size = size
        self.message = message
        self.rand = rand
        self.md5_hash = md5_hash

    def pack(self) -> bytes:
        message_bytes = self.message.encode("ascii")
        return struct.pack(
            f"!B{self.size}s{HASH_LENGTH}s{HASH_LENGTH}s",
            self.size,
            message_bytes,
            self.rand,
            self.md5_hash,
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 37:
            raise ValueError("Data too short for Chat unpacking")

        size = data[0]
        message, rand, md5_hash = struct.unpack(
            f"!{size}s{HASH_LENGTH}s{HASH_LENGTH}s", data[1 : 33 + size]
        )
        message = message.decode("ascii")

        return cls(size, message, rand, md5_hash)


class GeneralRequest:
    def __init__(self, code: MessageCode):
        self.code = code
        self.type = code.name

    def pack(self):
        raise NotImplementedError("Pack is not implemented")

    @classmethod
    def unpack(cls, data: bytes):
        raise NotImplementedError("Unpack is not implemented")


class PeerRequest(GeneralRequest):
    def __init__(self):
        super().__init__(MessageCode.PEER_REQUEST)

    def pack(self):
        return struct.pack("!B", self.code.value)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 1 or len(data) > 1:
            raise ValueError("Invalid data size for Request unpacking")

        code = RequestType(data[0])
        return cls(code)


class ArchiveRequest(GeneralRequest):
    def __init__(self):
        super().__init__(MessageCode.ARCHIVE_REQUEST)

    def pack(self):
        return struct.pack("!B", self.code.value)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 1 or len(data) > 1:
            raise ValueError("Invalid data size for Request unpacking")

        code = RequestType(data[0])
        return cls(code)


class GeneralResponse:
    def __init__(self, code: ResponseType):
        self.code = code
        self.type = code.name

    def pack(self):
        raise NotImplementedError("Pack is not implemented")

    @classmethod
    def unpack(cls, data: bytes):
        raise NotImplementedError("Unpack is not implemented")


class PeerList(GeneralResponse):
    def __init__(self, known_peers_amount: int, known_peers: List[str]):
        super().__init__(MessageCode.PEER_RESPONSE)

        if known_peers_amount != len(known_peers):
            raise ValueError(
                "Known peers amount does not match the number of peers provided"
            )

        self.known_peers_amount = known_peers_amount
        self.known_peers = known_peers

    def pack(self):
        return struct.pack("!BI", self.code.value, self.known_peers_amount) + b"".join(
            struct.pack("!I", peer) for peer in self.known_peers
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 5:
            raise ValueError("Invalid data size for PeerList unpacking")

        _, known_peers_amount = struct.unpack("!BI", data[:5])
        if len(data) != 5 + known_peers_amount * 4:
            raise ValueError("Data size does not match known peers amount")

        known_peers = []

        for i in range(known_peers_amount):
            start = 5 + i * 4
            end = start + 4
            peer = struct.unpack("!I", data[start:end])[0]
            known_peers.append(peer)

        return cls(known_peers_amount, known_peers)


class ArchiveResponse(GeneralResponse):
    def __init__(self, chat_amount: int = 0, chats: List[Chat] = []):
        super().__init__(MessageCode.PEER_RESPONSE)

        if chat_amount != len(chats):
            raise ValueError("chat_amount does not match the number of chats provided")

        self.chat_amount = chat_amount
        self.chats = chats

    def pack(self):
        return struct.pack("!BI", self.code.value, self.chat_amount) + b"".join(
            chat.pack() for chat in self.chats
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 5:
            raise ValueError("Invalid data size for ArchiveResponse unpacking")

        _, chat_amount = struct.unpack("!BI", data[:5])
        if len(data) != 5 + chat_amount * (1 + HASH_LENGTH + HASH_LENGTH + 1):
            raise ValueError("Data size does not match chat amount")

        chats = []
        offset = 5
        for _ in range(chat_amount):
            chat_data = data[offset:]
            chat = Chat.unpack(chat_data)
            chats.append(chat)
            offset += 1 + chat.size + HASH_LENGTH + HASH_LENGTH

        return cls(chat_amount, chats)


class P2PChatEngine:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

        self.sock = None
        self.lock = threading.Lock()
        self.server_thread = None
        self.sender_thread = None
        self.active_connections: dict[str, Tuple[str, int]] = {}

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

                if message_type == MessageCode.PEER_REQUEST.name:
                    peer_response = PeerList(
                        known_peers_amount=len(self.active_connections),
                        known_peers=list(self.active_connections.keys()),
                    )
                    conn_sock.sendall(peer_response.pack())
        except Exception as e:
            print(
                f"Error in listener for {addr}: {e}"
            )
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
                                request = PeerRequest()
                                peer_conn.sendall(request.pack())
                                print(f"Sent {request.type} to {peer_addr}")
                            except Exception as e:
                                print(f"Error sending to {peer_addr}: {e}")
                except Exception as e:
                    print(f"Error in sender: {e}")
            time.sleep(PEER_REQUEST_INTERVAL)

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
