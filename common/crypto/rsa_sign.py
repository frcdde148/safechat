"""RSA-1024 signing and verification helpers.

The implementation will wrap a mature crypto library. Keep RSA usage focused
on non-repudiation for key chat and file actions, not bulk encryption.
"""


SIGNED_ACTIONS = {
    "CHAT_SEND",
    "CHAT_RECV",
    "CHAT_ACK",
    "FILE_SEND",
    "FILE_RECV",
    "FILE_ACK",
}
