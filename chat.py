import argparse
import struct
import socket
from enum import Enum
from typing import List, Literal
import threading
import time

PORT = 51511


class Utils:
    @staticmethod
    def get_message_type_from_code(code: int) -> str:
        try:
            return MessageCode(code)
        except ValueError:
            raise ValueError(f"Unknown message code: {hex(code)}")


class MessageCode(Enum):
    PEER_REQUEST = 0x1
    PEER_RESPONSE = 0x2
    ARCHIVE_REQUEST = 0x3
    ARCHIVE_RESPONSE = 0x4

    def __str__(self):
        return self.value


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

    def start(self):
        print(f"Starting P2P Chat Engine on {self.ip}:{self.port}")

        addrinfo = socket.getaddrinfo(self.ip, None)
        family = addrinfo[0][0]
        self.sock = socket.socket(family, socket.SOCK_STREAM)

        self.lock = threading.Lock()

        threading.Thread(target=self.__listener, daemon=True).start()
        threading.Thread(target=self.__sender, daemon=True).start()

    def __listener(self):
        while True:
            byte = self.sock.recv(1)

            print(f"Received byte: {byte.hex()}")
            type_ = Utils.get_message_type_from_code(byte[0])
            print(f"Message type: {type_}")

    def __sender(self):
        while True:
            with self.lock:
                try:
                    request = Request(MessageCode.PEER_REQUEST)
                    packed_request = request.pack()

                    print(f"Sending request: {packed_request.hex()}")

                    self.sock.sendall(packed_request)
                except Exception as e:
                    print(f"Error: {e}")
            time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="DCC Internet P2P Blockchain Chat CLI")

    parser.add_argument("ip", help="IP address of self.")

    args = parser.parse_args()

    ip = args.ip

    engine = P2PChatEngine(ip, PORT)

    engine.start()


if __name__ == "__main__":
    main()
