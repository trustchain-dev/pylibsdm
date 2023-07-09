# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

from typing import Self

import ndef
from pydantic import AnyHttpUrl, BaseModel


class URLParamConfig(BaseModel):
    """Configuration for an SDM-capable URL NDEF record."""

    base_url: AnyHttpUrl

    def get_file_settings(self) -> "FileSettings":
        raise NotImplementedError()

    def get_url(self) -> str:
        raise NotImplementedError()

    def get_file_data(self) -> bytes:
        message = b"".join(ndef.message_encoder([ndef.UriRecord(iri=self.get_url())]))
        if len(message) > 253:
            raise ValueError("Message is too long")
        return b"\x00" + len(message).to_bytes() + message


class FileSettings(BaseModel):
    @classmethod
    def for_url(cls, config: URLParamConfig) -> tuple[Self, str]:
        raise NotImplementedError()
