# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

from typing import Self

from ndef import UriRecord
from pydantic import AnyHttpUrl, BaseModel


class URLParamConfig(BaseModel):
    """Configuration for an SDM-capable URL NDEF record."""

    base_url: AnyHttpUrl

    def get_file_settings(self) -> "FileSettings":
        raise NotImplementedError()

    def get_file_data(self) -> bytes:
        record = UriRecord(iri=self.base_url)
        return record.data


class FileSettings(BaseModel):
    @classmethod
    def for_url(cls, config: URLParamConfig) -> tuple[Self, str]:
        raise NotImplementedError()
