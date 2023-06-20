from binascii import unhexlify
from struct import pack, unpack
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad

from ..util import NULL_IV, bytes_xor


class ParamValidator:
    k_sdm_file_read: bytes
    k_sdm_meta_read: bytes

    uid: Optional[bytes]
    read_ctr: Optional[int]

    def __init__(self, k_sdm_file_read: bytes = 16*b"\0", k_sdm_meta_read: bytes = 16*b"\0"):
        self.k_sdm_file_read = k_sdm_file_read
        self.k_sdm_meta_read = k_sdm_meta_read

        self.uid = None
        self.read_ctr = None

    def generate_sdm_session_key(self):
        sv_1 = b"\xc3\x3c\x00\x01\x00\x80"
        sv_2 = b"\x3c\xc3\x00\x01\x00\x80"

        if self.uid is not None:
            sv_1 += self.uid
            sv_2 += self.uid

        if self.read_ctr is not None:
            sv_1 += pack("<L", self.read_ctr)[:3]
            sv_2 += pack("<L", self.read_ctr)[:3]

        cmac = CMAC.new(self.k_sdm_file_read, ciphermod=AES)
        cmac.update(sv_1)
        k_ses_sdm_file_read_enc = cmac.digest()

        cmac = CMAC.new(self.k_sdm_file_read, ciphermod=AES)
        cmac.update(sv_2)
        k_ses_sdm_file_read_mac = cmac.digest()

        return k_ses_sdm_file_read_enc, k_ses_sdm_file_read_mac

    def decrypt_picc_data(self, e_picc_data: str):
        cipher = AES.new(self.k_sdm_meta_read, AES.MODE_CBC, NULL_IV)
        picc_data = cipher.decrypt(unhexlify(e_picc_data))

        picc_data_tag = ord(picc_data[0:1])

        uid_mirror = bool(picc_data_tag & 128)
        read_ctr_mirror = bool(picc_data_tag & 64)
        uid_length = picc_data_tag & 7

        uid = picc_data[1:uid_length+1]
        read_ctr = unpack("<L", picc_data[uid_length+1:uid_length+4] + b"\0")[0]

        if uid_mirror:
            self.uid = uid
        if read_ctr_mirror:
            self.read_ctr = read_ctr
