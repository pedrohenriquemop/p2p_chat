import unittest
import os
import hashlib
from chat import Chat, ChatHistory, HASH_LENGTH  # Import from your classes file


class TestChat(unittest.TestCase):

    def setUp(self):
        self.initial_history = ChatHistory(chats=[])

    def test_chat_initialization(self):
        message = "TestMessage"
        rand_val = os.urandom(HASH_LENGTH)
        md5_hash_val = os.urandom(HASH_LENGTH)

        chat = Chat(message, self.initial_history, rand=rand_val, md5_hash=md5_hash_val)
        self.assertEqual(chat.size, len(message))
        self.assertEqual(chat.message, message)
        self.assertEqual(chat.rand, rand_val)
        self.assertEqual(chat.md5_hash, md5_hash_val)

        message_mine = "MiningChat"
        mined_chat = Chat(message_mine, self.initial_history)
        self.assertEqual(mined_chat.size, len(message_mine))
        self.assertEqual(mined_chat.message, message_mine)
        self.assertEqual(len(mined_chat.rand), HASH_LENGTH)
        self.assertEqual(len(mined_chat.md5_hash), HASH_LENGTH)
        self.assertTrue(mined_chat.md5_hash.startswith(b"\x00\x00"))

    def test_chat_initialization_invalid_message_length(self):
        with self.assertRaises(ValueError):
            Chat("A" * 256, self.initial_history)

    def test_chat_initialization_non_alphanumeric(self):
        with self.assertRaises(ValueError):
            Chat("Hello!", self.initial_history)

    def test_chat_pack_unpack(self):
        message = "PackUnpackTest"
        chat = Chat(message, self.initial_history)

        packed_chat = chat.pack()
        self.assertIsInstance(packed_chat, bytes)
        self.assertEqual(len(packed_chat), 1 + chat.size + HASH_LENGTH * 2)

        unpacked_chat = Chat.unpack(packed_chat)
        self.assertEqual(chat, unpacked_chat)

    def test_chat_unpack_invalid_data_too_short(self):
        with self.assertRaises(ValueError):
            Chat.unpack(b"\x01")

    def test_chat_unpack_incomplete_message_data(self):
        message_len = 10
        incomplete_data = b"\x0aabcdefghij"
        with self.assertRaises(ValueError):
            Chat.unpack(incomplete_data)


class TestChatHistory(unittest.TestCase):

    def setUp(self):
        self.history = ChatHistory(chats=[])
        self.chat1 = Chat("First", self.history)
        self.history.add_chat_in_history(self.chat1)
        self.chat2 = Chat("Second", self.history)
        self.history.add_chat_in_history(self.chat2)
        self.chat3 = Chat("Third", self.history)
        self.history.add_chat_in_history(self.chat3)

    def test_add_chat_in_history_valid(self):
        self.assertEqual(len(self.history.history), 3)
        self.assertTrue(self.history.verify_history())

        new_chat = Chat("NewChat", self.history)
        self.history.add_chat_in_history(new_chat)
        self.assertEqual(len(self.history.history), 4)
        self.assertTrue(self.history.verify_history())

    def test_add_chat_in_history_invalid_type(self):
        with self.assertRaises(TypeError):
            self.history.add_chat_in_history("not a chat object")

    def test_add_chat_in_history_invalid_chat(self):
        invalid_rand = os.urandom(HASH_LENGTH)
        invalid_hash = b"\x01\x01" + os.urandom(HASH_LENGTH - 2)
        invalid_chat = Chat(
            "InvalidChat", self.history, rand=invalid_rand, md5_hash=invalid_hash
        )

        with self.assertRaises(ValueError):
            self.history.add_chat_in_history(invalid_chat)

    def test_verify_history_empty(self):
        empty_history = ChatHistory(chats=[])
        self.assertTrue(empty_history.verify_history())

    def test_verify_history_valid_chain(self):
        self.assertTrue(self.history.verify_history())

    def test_verify_history_tampered_message(self):
        tampered_history = ChatHistory(chats=list(self.history.history))

        tampered_chat_idx = 1
        tampered_history.history[tampered_chat_idx].message = "TAMPERED"
        tampered_history.history[tampered_chat_idx].size = len("TAMPERED")
        tampered_history.history[tampered_chat_idx]._message_bytes = b"TAMPERED"

        self.assertFalse(tampered_history.verify_history())

    def test_verify_history_tampered_rand(self):
        tampered_history = ChatHistory(chats=list(self.history.history))

        tampered_chat_idx = 1
        tampered_history.history[tampered_chat_idx].rand = os.urandom(HASH_LENGTH)

        self.assertFalse(tampered_history.verify_history())

    def test_verify_history_tampered_hash(self):
        tampered_history = ChatHistory(chats=list(self.history.history))

        tampered_chat_idx = 1
        tampered_history.history[tampered_chat_idx].md5_hash = b"\x11" * HASH_LENGTH

        self.assertFalse(tampered_history.verify_history())

    def test_verify_history_last_20_chats_rule(self):
        long_history = ChatHistory(chats=[])
        for i in range(25):
            chat = Chat(f"Chat{i}", long_history)
            long_history.add_chat_in_history(chat)

        self.assertEqual(len(long_history.history), 25)
        self.assertTrue(long_history.verify_history())

        tampered_long_history = ChatHistory(chats=list(long_history.history))
        tampered_long_history.history[0].message = "BAD"
        tampered_long_history.history[0].size = len("BAD")
        tampered_long_history.history[0]._message_bytes = b"BAD"

        self.assertFalse(tampered_long_history.verify_history())

    def test_mine_chat_hash_starts_with_two_zeros(self):
        message = "MiningTest"
        temp_chat = Chat(
            message,
            self.history,
            rand=b"\x00" * HASH_LENGTH,
            md5_hash=b"\x00" * HASH_LENGTH,
        )

        rand, md5_hash = self.history.mine_chat_hash(temp_chat)
        self.assertEqual(len(rand), HASH_LENGTH)
        self.assertEqual(len(md5_hash), HASH_LENGTH)
        self.assertTrue(md5_hash.startswith(b"\x00\x00"))


if __name__ == "__main__":
    unittest.main(argv=["first-arg-is-ignored"], exit=False)
