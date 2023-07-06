# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""(JSON) API definitions for provisioning of NFC tags."""

from typing import Union

import nfc
from pydantic import BaseModel, Field, NonNegativeInt, SecretBytes

from ..tag.structs import FileSettings, URLParamConfig
from ..tag.tag import Tag


TagModule = Tag.get_tag_modules_enum()


class RawFileConfig(BaseModel):
    """Manual configuration of all file attributes and data."""

    settings: Union[tuple(FileSettings.__subclasses__())] = Field(
        "Settings for the file to deploy"
    )
    # FIXME add data

    def get_file_settings(self) -> FileSettings:
        return self.settings


class TagConfig(BaseModel):
    """Configuration container for an NFC tag."""

    keys: dict[NonNegativeInt, SecretBytes] = Field(
        description="Set of keys to change on tag", default_factory=dict
    )
    files: dict[
        NonNegativeInt, Union[tuple(URLParamConfig.__subclasses__())] | RawFileConfig
    ] = Field(description="Set of files to change on tag", default_factory=dict)


class ProvisionResult(BaseModel):
    """Result of a provisioning job."""

    tag_uid: bytes = Field(description="UID of provisioned NFC tag")
    # FIXME add status of some sort


class ProvisionJob(BaseModel):
    """Job definition for a tag provisioning job."""

    tag_module: TagModule = Field(
        description="Name of tag module supporting target tag type"
    )

    keys: Optional[dict[NonNegativeInt, SecretBytes]] = Field(
        default=None, description="Current set of cryptographic keys (if needed)"
    )
    tag_config: TagConfig = Field(description="Configuration to provision to tag")

    def run(self, nfc_tag: nfc.tag.Tag) -> ProvisionResult:
        """Provision one tag"""
        # FIXME proper logging, error handling, ProvisionResult generation
        # FIXME should we get an sdm_tag directly?
        sdm_tag: Tag = Tag.get_tag_module(self.tag_module).Tag(nfc_tag, self.keys)

        for key_nr, key in self.tag_config.keys.items():
            sdm_tag.change_key(key_nr, key)

        for file_nr, file_config in self.tag_config.files.items():
            sdm_tag.change_file_settings(file_nr, file_settings)
            # FIXME write file data here
