import argparse
import os
import struct
import socket
from enum import Enum
from typing import List, Literal, Tuple
import threading
import time
import traceback
import hashlib

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
    def __init__(
        self,
        message: str,
        chat_history: "ChatHistory",
        verifier_code: bytes = None,
        md5_hash: bytes = None,
    ):
        self.size = len(message)

        if not (0 <= self.size <= 255):
            raise ValueError("Message length (size) must be between 0 and 255.")

        if not message.encode("ascii").isascii() and message != "":
            raise ValueError("Chat message must contain only ascii characters.")

        try:
            self._message_bytes = message.encode("ascii")
            self.message = message
        except UnicodeEncodeError:
            raise ValueError("Chat message must be ASCII.")

        if verifier_code is not None and md5_hash is not None:
            if len(verifier_code) != HASH_LENGTH:
                raise ValueError(
                    f"Provided verifier_code must be {HASH_LENGTH} bytes long."
                )
            if len(md5_hash) != HASH_LENGTH:
                raise ValueError(f"Provided MD5 hash must be {HASH_LENGTH} bytes long.")
            self.verifier_code = verifier_code
            self.md5_hash = md5_hash
        else:
            self.verifier_code, self.md5_hash = chat_history.mine_chat_hash(self)

    def pack(self) -> bytes:
        return struct.pack(
            f"!B{self.size}s{HASH_LENGTH}s{HASH_LENGTH}s",
            self.size,
            self._message_bytes,
            self.verifier_code,
            self.md5_hash,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "Chat":
        if len(data) < (1 + HASH_LENGTH + HASH_LENGTH):
            raise ValueError("Data too short for Chat unpacking.")

        size = data[0]

        expected_total_len = 1 + size + HASH_LENGTH + HASH_LENGTH
        if len(data) < expected_total_len:
            raise ValueError(
                f"Data incomplete for chat message. Expected {expected_total_len} bytes, got {len(data)}."
            )

        unpacked_tuple = struct.unpack(
            f"!{size}s{HASH_LENGTH}s{HASH_LENGTH}s", data[1:expected_total_len]
        )

        message_bytes = unpacked_tuple[0]
        verifier_code_bytes = unpacked_tuple[1]
        md5_hash_bytes = unpacked_tuple[2]

        message_str = message_bytes.decode("ascii")

        return cls(
            message_str,
            None,
            verifier_code=verifier_code_bytes,
            md5_hash=md5_hash_bytes,
        )

    def __repr__(self):
        return (
            f"Chat(size={self.size}, message='{self.message}', "
            f"verifier_code={self.verifier_code.hex()}, md5_hash={self.md5_hash.hex()})"
        )

    def __eq__(self, other):
        if not isinstance(other, Chat):
            return NotImplemented
        return (
            self.size == other.size
            and self.message == other.message
            and self.verifier_code == other.verifier_code
            and self.md5_hash == other.md5_hash
        )


class ChatHistory:
    def __init__(self, chats: List["Chat"]):
        self.history = chats

    def add_chat_in_history(self, chat: Chat):
        if not isinstance(chat, Chat):
            raise TypeError("chat must be an instance of Chat")

        if not self.verify_chat_validity(chat):
            raise ValueError(
                "Chat is not valid for history based on mining criteria or hash chain."
            )

        self.history.append(chat)

    def verify_chat_validity(self, chat: Chat) -> bool:
        s_sequence_bytes = self._get_s_sequence(chat, for_mining=False)
        calculated_md5 = hashlib.md5(s_sequence_bytes).digest()

        if not calculated_md5.startswith(b"\x00\x00"):
            return False

        if chat.md5_hash != calculated_md5:
            return False

        return True

    def _get_s_sequence(self, chat: Chat, for_mining: bool = False) -> bytes:
        temp_history_for_s = list(self.history)

        temp_chat_for_s = Chat(
            message=chat.message,
            chat_history=self,
            verifier_code=chat.verifier_code,
            md5_hash=b"\x00" * HASH_LENGTH if for_mining else chat.md5_hash,
        )

        temp_history_for_s.append(temp_chat_for_s)

        start_index = max(0, len(temp_history_for_s) - 20)
        relevant_chats = temp_history_for_s[start_index:]

        s_bytes = b""
        for c in relevant_chats:
            s_bytes += c.pack()

        return s_bytes[:-HASH_LENGTH]

    def mine_chat_hash(self, chat_to_mine: Chat) -> Tuple[bytes, bytes]:
        attempts = 0
        MINING_ATTEMPTS_LIMIT = 2_000_000

        while attempts < MINING_ATTEMPTS_LIMIT:
            current_verifier_code = os.urandom(HASH_LENGTH)
            chat_to_mine.verifier_code = current_verifier_code

            s_sequence_bytes = self._get_s_sequence(chat_to_mine, for_mining=True)
            calculated_md5 = hashlib.md5(s_sequence_bytes).digest()

            if calculated_md5.startswith(b"\x00\x00"):
                return current_verifier_code, calculated_md5

            attempts += 1

        raise RuntimeError(f"Mining failed after {MINING_ATTEMPTS_LIMIT} attempts.")

    def verify_history(self) -> bool:
        if not self.history:
            return True

        for i in range(len(self.history)):
            current_chat = self.history[i]

            temp_history_for_s_calc = ChatHistory(self.history[:i])
            s_sequence_bytes = temp_history_for_s_calc._get_s_sequence(
                current_chat, for_mining=False
            )
            calculated_hash_for_s = hashlib.md5(s_sequence_bytes).digest()

            if not current_chat.md5_hash.startswith(b"\x00\x00"):
                return False

            if current_chat.md5_hash != calculated_hash_for_s:
                return False

        return True

    def history_count(self) -> int:
        return len(self.history)

    def __repr__(self):
        return f"ChatHistory(chats_count={len(self.history)})"


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
        if len(data) != 1:
            raise ValueError("Invalid data size for PeerRequest unpacking")

        code_val = data[0]
        if code_val != MessageCode.PEER_REQUEST.value:
            raise ValueError(
                f"PeerRequest code mismatch. Expected {MessageCode.PEER_REQUEST.value}, got {code_val}."
            )

        return cls()


class ArchiveRequest(GeneralRequest):
    def __init__(self):
        super().__init__(MessageCode.ARCHIVE_REQUEST)

    def pack(self):
        return struct.pack("!B", self.code.value)

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) != 1:
            raise ValueError("Invalid data size for ArchiveRequest unpacking")

        code_val = data[0]
        if code_val != MessageCode.ARCHIVE_REQUEST.value:
            raise ValueError(
                f"ArchiveRequest code mismatch. Expected {MessageCode.ARCHIVE_REQUEST.value}, got {code_val}."
            )

        return cls()


class GeneralResponse:
    def __init__(self, code: MessageCode):
        self.code = code
        self.type = code.name

    def pack(self):
        raise NotImplementedError("Pack is not implemented")

    @classmethod
    def unpack(cls, data: bytes):
        raise NotImplementedError("Unpack is not implemented")


class PeerList(GeneralResponse):
    def __init__(self, known_peers_amount: int, known_peers: List[Tuple[str, int]]):
        super().__init__(MessageCode.PEER_RESPONSE)

        if known_peers_amount != len(known_peers):
            raise ValueError(
                "Known peers amount does not match the number of peers provided"
            )

        self.known_peers_amount = known_peers_amount
        self.known_peers = known_peers

    def pack(self):
        packed_code = struct.pack("!B", self.code.value)
        packed_amount = struct.pack("!I", self.known_peers_amount)

        packed_peers_data = b"".join(
            socket.inet_aton(peer_ip) for peer_ip, _ in self.known_peers
        )

        return packed_code + packed_amount + packed_peers_data

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < 5:
            raise ValueError("Invalid data size for PeerList unpacking")

        code_value, known_peers_amount = struct.unpack("!BI", data[:5])

        if code_value != MessageCode.PEER_RESPONSE.value:
            raise ValueError(
                f"Message code mismatch for PeerList. Expected {MessageCode.PEER_RESPONSE.value}, got {code_value}."
            )

        expected_total_size = 5 + known_peers_amount * 4
        if len(data) != expected_total_size:
            raise ValueError(
                f"Data size ({len(data)}) does not match expected size ({expected_total_size}) based on known peers amount ({known_peers_amount})."
            )

        unpacked_peers_list: List[Tuple[str, int]] = []

        for i in range(known_peers_amount):
            start = 5 + i * 4
            end = start + 4

            ip_bytes = data[start:end]

            peer_ip_str = socket.inet_ntoa(ip_bytes)
            unpacked_peers_list.append((peer_ip_str, PORT))

        return cls(known_peers_amount, unpacked_peers_list)


class ArchiveResponse(GeneralResponse):
    def __init__(self, chats: List[Chat]):
        super().__init__(MessageCode.ARCHIVE_RESPONSE)
        self.chats = chats
        self.chat_amount = len(chats)

    def pack(self):
        header = struct.pack("!BI", self.code.value, self.chat_amount)
        chats_data = b"".join(chat.pack() for chat in self.chats)
        return header + chats_data

    @classmethod
    def unpack(cls, data: bytes) -> "ArchiveResponse":
        if len(data) < 5:
            raise ValueError("Invalid data size for ArchiveResponse unpacking")

        code_value, chat_amount = struct.unpack("!BI", data[:5])
        if code_value != MessageCode.ARCHIVE_RESPONSE.value:
            raise ValueError(
                f"Message code mismatch for ArchiveResponse. Expected {MessageCode.ARCHIVE_RESPONSE.value}, got {code_value}."
            )

        unpacked_chats: List[Chat] = []
        offset = 5
        for _ in range(chat_amount):
            if offset >= len(data):
                raise ValueError(
                    f"Not enough data to unpack chat {len(unpacked_chats) + 1} of {chat_amount}."
                )

            chat = Chat.unpack(data[offset:])
            unpacked_chats.append(chat)
            offset += 1 + chat.size + HASH_LENGTH + HASH_LENGTH

        return cls(chats=unpacked_chats)


class P2PChatEngine:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = None
        self.lock = threading.Lock()
        self.server_thread = None
        self.sender_thread = None
        self.active_connections: dict[Tuple[str, int], socket.socket] = {}
        self.chat_history = ChatHistory(chats=[])

    def start(self):
        print(f"Starting P2P Chat Engine on {self.ip}:{self.port}")

        addrinfo = socket.getaddrinfo(
            self.ip, self.port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
        )
        family, socktype, proto, canonname, sa = addrinfo[0]
        self.sock = socket.socket(family, socktype, proto)
        self.sock.settimeout(1.0)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            self.sock.bind(sa)
            self.sock.listen(5)
            print(f"Listening on {self.ip}:{self.port}")
        except OSError as e:
            print(f"Error binding socket to {self.ip}:{self.port}: {e}")
            return

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

    def __listener(self, conn_sock: socket.socket, addr: Tuple[str, int]):
        try:
            while True:
                header_byte = conn_sock.recv(1)
                if not header_byte:
                    print(f"Connection closed by {addr}")
                    break

                message_code_int = header_byte[0]
                message_type = Utils.get_message_type_from_code(message_code_int)
                # print(f"> Received message type: {message_type} from {addr}")

                if message_type == MessageCode.PEER_REQUEST.name:
                    peer_response = PeerList(
                        known_peers_amount=len(self.active_connections),
                        known_peers=list(self.active_connections.keys()),
                    )
                    packed_response = peer_response.pack()
                    conn_sock.sendall(packed_response)
                    # print(f"> Sent PeerList to {addr}: {packed_response.hex()}")

                elif message_type == MessageCode.PEER_RESPONSE.name:
                    length_bytes = self.__recv_all(conn_sock, 4)
                    if not length_bytes:
                        break

                    known_peers_amount = struct.unpack("!I", length_bytes)[0]
                    peers_data = self.__recv_all(conn_sock, known_peers_amount * 4)
                    if not peers_data:
                        break

                    peer_list_response = PeerList.unpack(
                        header_byte + length_bytes + peers_data
                    )
                    # print(
                    #     f"> Received PeerList from {addr}: {peer_list_response.known_peers}"
                    # )

                    for peer_ip, _ in peer_list_response.known_peers:
                        if (
                            peer_ip != self.ip
                            and (peer_ip, PORT) not in self.active_connections
                        ):
                            self.connect_to_peer(peer_ip)

                elif message_type == MessageCode.ARCHIVE_REQUEST.name:
                    archive_response = ArchiveResponse(chats=self.chat_history.history)
                    packed_response = archive_response.pack()
                    conn_sock.sendall(packed_response)
                    print(
                        f"> Sent ArchiveResponse to {addr} with {self.chat_history.history_count()} chats."
                    )

                elif message_type == MessageCode.ARCHIVE_RESPONSE.name:
                    length_bytes = self.__recv_all(conn_sock, 4)
                    if not length_bytes:
                        break

                    chat_amount = struct.unpack("!I", length_bytes)[0]

                    unpacked_chats: List[Chat] = []
                    for _ in range(chat_amount):
                        chat_size_byte = self.__recv_all(conn_sock, 1)
                        if not chat_size_byte:
                            print(
                                f"> Received incomplete chat data (missing N) from {addr}. Breaking."
                            )
                            break
                        current_chat_N = chat_size_byte[0]

                        # 1 (for N) + N (message bytes) + 16 (verifier_code) + 16 (md5_hash)
                        expected_chat_data_len = (
                            current_chat_N + HASH_LENGTH * 2
                        )  # N + 16 + 16 = N + 32 bytes for the rest

                        remaining_chat_data = self.__recv_all(
                            conn_sock, expected_chat_data_len
                        )
                        if not remaining_chat_data:
                            print(
                                f"> Received incomplete chat data (body) from {addr}. Breaking."
                            )
                            break

                        full_chat_packed_data = chat_size_byte + remaining_chat_data

                        try:
                            chat = Chat.unpack(full_chat_packed_data)
                            unpacked_chats.append(chat)
                        except ValueError as ve:
                            print(
                                f"> Error unpacking single chat from {addr}: {ve}. Skipping this chat."
                            )

                    if len(unpacked_chats) != chat_amount:
                        print(
                            f"> Warning: Unpacked {len(unpacked_chats)} chats, but expected {chat_amount} from {addr}. History might be incomplete/corrupted."
                        )

                    if unpacked_chats:
                        received_history_instance = ChatHistory(chats=unpacked_chats)
                        if received_history_instance.verify_history():
                            print("> Received history verified correctly.")
                            if (
                                received_history_instance.history_count()
                                > self.chat_history.history_count()
                            ):
                                print(
                                    "> New history is longer. Replacing current history."
                                )
                                self.chat_history = received_history_instance
                            else:
                                print(
                                    "> New history is not longer or equal. Keeping current history."
                                )
                        else:
                            print("> Received history FAILED verification. Ignoring.")
                    else:
                        print(
                            f"> No valid chats unpacked from ArchiveResponse from {addr}. Ignoring history."
                        )

                else:
                    print(
                        f"> Unknown message code {hex(message_code_int)} from {addr}. Ignoring."
                    )

        except Exception as e:
            print(f"Error in listener for {addr}: {e}")
            traceback.print_stack()
        finally:
            conn_sock.close()
            with self.lock:
                if addr in self.active_connections:
                    del self.active_connections[addr]

    def __recv_all(self, sock: socket.socket, n_bytes: int) -> bytes:
        data = b""
        while len(data) < n_bytes:
            packet = sock.recv(n_bytes - len(data))
            if not packet:
                return b""
            data += packet
        return data

    def __sender(self):
        while True:
            with self.lock:
                connections_to_send = list(self.active_connections.items())

            if not connections_to_send:
                pass
            else:
                for peer_addr, peer_conn in connections_to_send:
                    try:
                        request = PeerRequest()
                        packed_request = request.pack()
                        peer_conn.sendall(packed_request)
                    except Exception as e:
                        print(f"Error sending to {peer_addr}: {e}")
                        with self.lock:
                            if peer_addr in self.active_connections:
                                self.active_connections[peer_addr].close()
                                del self.active_connections[peer_addr]
            time.sleep(PEER_REQUEST_INTERVAL)

    def connect_to_peer(self, peer_ip: str):
        if not peer_ip:
            raise ValueError("Peer IP cannot be empty")

        if peer_ip == self.ip:
            print("! Cannot connect to self. Skipping.")
            return False

        try:
            peer_addr = (peer_ip, PORT)
            with self.lock:
                if peer_addr in self.active_connections:
                    return True

            client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_sock.settimeout(5.0)
            client_sock.connect(peer_addr)
            print(f"! Connected to {peer_ip}:{PORT}")

            with self.lock:
                self.active_connections[peer_addr] = client_sock
            threading.Thread(
                target=self.__listener, args=(client_sock, peer_addr), daemon=True
            ).start()
            return True
        except Exception as e:
            print(f"! Could not connect to peer {peer_ip}:{PORT}: {e}")
            return False

    def _send_archive_request_to_all(self):
        with self.lock:
            connections_to_send = list(self.active_connections.items())

        if not connections_to_send:
            print("No active connections to request archive from.")
            return

        request = ArchiveRequest()
        packed_request = request.pack()
        for peer_addr, peer_conn in connections_to_send:
            try:
                peer_conn.sendall(packed_request)
                print(f"Sent ArchiveRequest to {peer_addr}")
            except Exception as e:
                print(f"Error sending ArchiveRequest to {peer_addr}: {e}")
                with self.lock:
                    if peer_addr in self.active_connections:
                        self.active_connections[peer_addr].close()
                        del self.active_connections[peer_addr]

    def _send_chat_message_to_all(self, message: str):
        try:
            new_chat = Chat(message=message, chat_history=self.chat_history)
            self.chat_history.add_chat_in_history(new_chat)
            print(
                f"Chat '{message}' mined and added to history. Hash: {new_chat.md5_hash.hex()}"
            )

            self._disseminate_history()
        except ValueError as e:
            print(f"Error creating chat: {e}")
        except RuntimeError as e:
            print(f"Mining failed: {e}")

    def _disseminate_history(self):
        with self.lock:
            connections_to_send = list(self.active_connections.items())

        if not connections_to_send:
            print("No active connections to disseminate history to.")
            return

        archive_response = ArchiveResponse(chats=self.chat_history.history)
        packed_response = archive_response.pack()
        print(
            f"Disseminating history ({self.chat_history.history_count()} chats). Packed size: {len(packed_response)} bytes."
        )

        for peer_addr, peer_conn in connections_to_send:
            try:
                peer_conn.sendall(packed_response)
                print(f"Sent ArchiveResponse to {peer_addr}")
            except Exception as e:
                print(f"Error disseminating history to {peer_addr}: {e}")
                with self.lock:
                    if peer_addr in self.active_connections:
                        self.active_connections[peer_addr].close()
                        del self.active_connections[peer_addr]

    def __start_cli(self):
        commands = [
            {
                "description": "connect to a peer",
                "accepted": ["connect", "conn", "con", "c"],
                "args": ["ip"],
            },
            {
                "description": "list known peers",
                "accepted": ["list", "l", "peers", "p"],
                "args": [],
            },
            {
                "description": "send a chat message",
                "accepted": ["send", "s", "message", "m"],
                "args": ["message_text"],
            },
            {
                "description": "show chat history",
                "accepted": ["history", "h", "chats"],
                "args": [],
            },
            {
                "description": "request archive from peers",
                "accepted": ["request_archive", "ra"],
                "args": [],
            },
        ]

        print("\n--- Commands ---")
        for cmd in commands:
            args_str = ""
            if cmd["args"]:
                args_str = " " + " ".join(map(lambda x: f"<{x}>", cmd["args"]))
            print(f"> [{', '.join(cmd['accepted'])}]{args_str} to {cmd['description']}")
        print("> [exit] to terminate the program")
        print("----------------\n")

        while True:
            try:
                command_line = input("Enter command: ").strip()
                if not command_line:
                    continue

                if command_line.lower() == "exit":
                    print("Exiting CLI...")
                    self.sock.close()
                    break

                parts = command_line.split(" ", 1)
                cmd_verb = parts[0].lower()
                cmd_args_str = parts[1] if len(parts) > 1 else ""

                was_accepted = False

                if cmd_verb in commands[0]["accepted"]:  # connect
                    self.connect_to_peer(cmd_args_str)
                    was_accepted = True
                elif cmd_verb in commands[1]["accepted"]:  # list peers
                    print(f"Known peers: {list(self.active_connections.keys())}")
                    was_accepted = True
                elif cmd_verb in commands[2]["accepted"]:  # send message
                    if cmd_args_str:
                        self._send_chat_message_to_all(cmd_args_str)
                    else:
                        print("Error: Message text required for 'send' command.")
                    was_accepted = True
                elif cmd_verb in commands[3]["accepted"]:  # show history
                    print("\n--- Chat History ---")
                    if not self.chat_history.history:
                        print("No chats in history yet.")
                    else:
                        for i, chat in enumerate(self.chat_history.history):
                            print(
                                f"[{i+1}] {chat.message} (Hash: {chat.md5_hash.hex()[:8]}...)"
                            )
                    print("--------------------\n")
                    was_accepted = True
                elif cmd_verb in commands[4]["accepted"]:  # request archive
                    self._send_archive_request_to_all()
                    was_accepted = True

                if not was_accepted:
                    print("Unknown command. Use one of the following:")
                    for cmd in commands:
                        args_str = ""
                        if cmd["args"]:
                            args_str = " " + " ".join(
                                map(lambda x: f"<{x}>", cmd["args"])
                            )
                        print(
                            f"> [{', '.join(cmd['accepted'])}]{args_str} to {cmd['description']}"
                        )

            except KeyboardInterrupt:
                print("\nExiting CLI...")
                self.sock.close()
                break
            except Exception as e:
                print(f"Error processing command: {e}")
                # traceback.print_exc()


def main():
    parser = argparse.ArgumentParser(description="DCC Internet P2P Blockchain Chat CLI")
    parser.add_argument("ip", help="IP address of self.")
    args = parser.parse_args()

    engine = P2PChatEngine(args.ip, PORT)
    engine.start()
    print("Program terminated.")


if __name__ == "__main__":
    main()
