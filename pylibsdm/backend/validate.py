# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import logging
import re
from binascii import hexlify, unhexlify
from struct import pack, unpack
from typing import Optional
from urllib.parse import parse_qsl, urlparse

import ndef
import nfc
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from ..tag.tag import Tag
from ..util import NULL_IV


logger = logging.getLogger(__name__)


class ParamValidator:
    # FIXME probably move most into NTAG 424 DNA class;
    #  reconsider whoe code structure
    k_sdm_file_read: bytes
    k_sdm_meta_read: bytes

    k_ses_sdm_file_read_enc: Optional[bytes]
    k_ses_sdm_file_read_mac: Optional[bytes]

    param_picc_data: Optional[str]
    param_enc_data: Optional[str]
    param_cmac: Optional[str]
    param_cmac_input: Optional[str]

    e_picc_data: Optional[str]
    e_file_data: Optional[str]
    cmac: Optional[str]

    picc_data: Optional[bytes]
    file_data: Optional[bytes]

    uid_mirror: bool
    read_ctr_mirror: bool

    uid: Optional[bytes]
    read_ctr: Optional[int]

    cmac_valid: bool

    def __init__(
        self,
#        tag_class: Tag | str,
        k_sdm_file_read: str = 16 * "00",
        k_sdm_meta_read: str = 16 * "00",
        param_picc_data: Optional[str] = None,
        param_enc_data: Optional[str] = None,
        param_cmac: Optional[str] = None,
        param_cmac_input: Optional[str] = None,
    ):
 #       if isinstance(tag_class, str):
 #           self.tag_class = Tag.get_tag_module(tag_class).Tag
 #       else:
 #           self.tag_class = tag_class

        self.k_sdm_file_read = unhexlify(k_sdm_file_read)
        self.k_sdm_meta_read = unhexlify(k_sdm_meta_read)

        self.k_ses_sdm_file_read_enc = None
        self.k_ses_sdm_file_read_mac = None

        self.param_picc_data = param_picc_data
        self.param_enc_data = param_enc_data
        self.param_cmac = param_cmac
        self.param_cmac_input = param_cmac_input

        self.e_picc_data = None
        self.e_file_data = None
        self.cmac = None

        self.picc_data = None
        self.file_data = None

        self.uid_mirror = False
        self.read_ctr_mirror = False

        self.uid = None
        self.read_ctr = None

        self.cmac_valid = False

    def parse_ndef(self, nfc_tag: nfc.tag.Tag):
        logger.debug("Reading NDEF of tag: %s", str(nfc_tag))

        for record in nfc_tag.ndef.records:
            if isinstance(record, ndef.uri.UriRecord):
                logger.info("Found URI record: %s", record.iri)
                try:
                    self.parse_uri(record.iri)
                    return
                except Exception as exc:
                    # FIXME explicitly handle exceptions
                    raise
                    logger.error("Could not parse URI: %s", exc)

        raise ValueError("No parsable NDEF record")

    def parse_uri(self, uri: str):
        logger.debug("Parsing URI <%s>", uri)

        params = dict(parse_qsl(urlparse(uri).query))
        logger.debug("Parsed query params: %s", params)

        if picc_data := params.get(self.param_picc_data):
            self.e_picc_data = picc_data
            logger.debug("Found picc_data: %s", picc_data)
            self.picc_data = self.decrypt_picc_data()
        else:
            logger.debug("No picc_data parameter found")

        if enc_data := params.get(self.param_enc_data):
            self.e_file_data = enc_data
            logger.debug("Found enc_data: %s", enc_data)
            self.file_data = self.decrypt_file_data()
        else:
            logger.debug("No enc_data parameter found")

        if cmac := params.get(self.param_cmac):
            self.cmac = cmac
            logger.debug("Found cmac: %s", cmac)
            if self.param_cmac_input:
                cmac_input = self.cmac_input_from_uri(
                    uri, self.param_cmac_input, self.param_cmac
                )
            else:
                cmac_input = None
            self.cmac_valid = self.validate_cmac(mac_input=cmac_input)
        else:
            logger.debug("No cmac parameter found")

    @staticmethod
    def cmac_input_from_uri(uri, param_cmac_input, param_cmac) -> str:
        i_cmac_input = (
            re.search(f"[?&]{param_cmac_input}=", uri).start()
            + 2
            + len(param_cmac_input)
        )
        i_cmac = re.search(f"[?&]{param_cmac}=", uri).start() + 2 + len(param_cmac)

        return uri[i_cmac_input:i_cmac]

    @property
    def ive(self) -> bytes:
        cipher = AES.new(self.k_ses_sdm_file_read_enc, AES.MODE_CBC, NULL_IV)
        return cipher.encrypt(pack("<L", self.read_ctr)[:3] + 13 * b"\0")

    def generate_sdm_session_keys(self):
        logger.debug("Generating SDM session keys")

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

    def decrypt_picc_data(self, e_picc_data: Optional[str] = None):
        e_picc_data = e_picc_data or self.e_picc_data
        if not e_picc_data:
            raise TypeError("Must provide e_picc_data as argument or in instance")

        cipher = AES.new(self.k_sdm_meta_read, AES.MODE_CBC, NULL_IV)
        picc_data = cipher.decrypt(unhexlify(e_picc_data))

        # FIXME refactor into dataclass; probably move into tag class
        #  ref for NTAG 424 DNA: page 38, table 21
        picc_data_tag = ord(picc_data[0:1])

        self.uid_mirror = bool(picc_data_tag & 128)
        self.read_ctr_mirror = bool(picc_data_tag & 64)
        uid_length = picc_data_tag & 7

        next_offset = 1
        if self.uid_mirror:
            self.uid = picc_data[next_offset : next_offset + uid_length]
            logger.info("UID mirrored: %s", hexlify(self.uid).decode())
            next_offset += uid_length
        else:
            logger.info("UID not mirrored")

        if self.read_ctr_mirror:
            self.read_ctr = unpack(
                "<L", picc_data[next_offset : next_offset + 3] + b"\0"
            )[0]
            logger.info("Read counter mirrored: %d", self.read_ctr)
            next_offset += 3
        else:
            logger.info("Read counter not mirrored")

    def decrypt_file_data(
        self, e_file_data: Optional[str] = None, e_picc_data: Optional[str] = None
    ):
        logger.debug("Decrypting file data")

        e_file_data = e_file_data or self.e_file_data
        if not e_file_data:
            raise TypeError("Must provide e_file_data as argument or in instance")

        e_picc_data = e_picc_data or self.e_picc_data
        if not e_picc_data:
            raise TypeError("Must provide e_picc_data as argument or in instance")

        if not self.picc_data:
            self.decrypt_picc_data(e_picc_data)
        if not self.k_ses_sdm_file_read_enc:
            self.generate_sdm_session_keys()

        cipher = AES.new(self.k_ses_sdm_file_read_enc, AES.MODE_CBC, self.ive)
        file_data = cipher.decrypt(unhexlify(e_file_data))

        return file_data

    def validate_cmac(
        self,
        cmac_provided: Optional[str] = None,
        e_picc_data: Optional[str] = None,
        mac_input: Optional[str] = None,
    ):
        cmac_provided = cmac_provided or self.cmac

        if not cmac_provided:
            raise TypeError("Must provide cmac as argument or in instance")

        logger.debug("Validating CMAC: %s", cmac_provided)

        e_picc_data = e_picc_data or self.e_picc_data
        if not e_picc_data:
            raise TypeError("Must provide e_picc_data as argument or in instance")

        if not self.picc_data:
            self.decrypt_picc_data(e_picc_data)
        if not self.k_ses_sdm_file_read_mac:
            self.generate_sdm_session_keys()

        cmac = CMAC.new(self.k_ses_sdm_file_read_mac, ciphermod=AES)
        if mac_input is not None:
            cmac.update(mac_input.encode())
        cmac_expected = cmac.digest()[1::2]

        if cmac_expected == unhexlify(cmac_provided):
            logger.info("CMAC matches: %s", cmac_provided.lower())
            return True
        else:
            logger.warning(
                "CMAC does not match: %s != %s",
                cmac_provided.lower(),
                hexlify(cmac_expected).decode(),
            )
            return False
