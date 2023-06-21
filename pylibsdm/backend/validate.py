from binascii import unhexlify
from struct import pack, unpack
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from ..util import NULL_IV


class ParamValidator:
    k_sdm_file_read: bytes
    k_sdm_meta_read: bytes

    uid: Optional[bytes]
    read_ctr: Optional[int]

    def __init__(self, k_sdm_file_read: bytes = 16 * b"\0", k_sdm_meta_read: bytes = 16 * b"\0"):
        self.k_sdm_file_read = k_sdm_file_read
        self.k_sdm_meta_read = k_sdm_meta_read

        self.uid = None
        self.read_ctr = None

    @property
    def ive(self) -> bytes:
        cipher = AES.new(self.k_ses_sdm_file_read_enc, AES.MODE_CBC, NULL_IV)
        return cipher.encrypt(pack("<L", self.read_ctr)[:3] + 13 * b"\0")

    def generate_sdm_session_keys(self):
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
        self.k_ses_sdm_file_read_enc = cmac.digest()

        cmac = CMAC.new(self.k_sdm_file_read, ciphermod=AES)
        cmac.update(sv_2)
        self.k_ses_sdm_file_read_mac = cmac.digest()

    def decrypt_picc_data(self, e_picc_data: str):
        cipher = AES.new(self.k_sdm_meta_read, AES.MODE_CBC, NULL_IV)
        picc_data = cipher.decrypt(unhexlify(e_picc_data))

        picc_data_tag = ord(picc_data[0:1])

        uid_mirror = bool(picc_data_tag & 128)
        read_ctr_mirror = bool(picc_data_tag & 64)
        uid_length = picc_data_tag & 7

        next_offset = 1
        if uid_mirror:
            self.uid = picc_data[next_offset : next_offset + uid_length]
            next_offset += uid_length
        if read_ctr_mirror:
            self.read_ctr = unpack("<L", picc_data[next_offset : next_offset + 3] + b"\0")[0]
            next_offset += 3

    def decrypt_file_data(self, e_file_data: str, e_picc_data: str):
        self.decrypt_picc_data(e_picc_data)
        self.generate_sdm_session_keys()

        cipher = AES.new(self.k_ses_sdm_file_read_enc, AES.MODE_CBC, self.ive)
        file_data = cipher.decrypt(unhexlify(e_file_data))

        return file_data

    def validate_cmac(self, cmac_provided: str, e_picc_data: str, mac_input: Optional[str] = None):
        self.decrypt_picc_data(e_picc_data)
        self.generate_sdm_session_keys()

        cmac = CMAC.new(self.k_ses_sdm_file_read_mac, ciphermod=AES)
        if mac_input is not None:
            cmac.update(mac_input.encode())
        cmac_expected = cmac.digest()[1::2]

        return cmac_expected == unhexlify(cmac_provided)
