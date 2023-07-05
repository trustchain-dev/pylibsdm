# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

"""(JSON) API definitions for provisioning of NFC tags."""

from typing import Union

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


class TagConfig(BaseModel):
    """Configuration container for an NFC tag."""

    keys: dict[NonNegativeInt, SecretBytes] = Field("Set of keys to change on tag")
    files: dict[
        NonNegativeInt, Union[tuple(URLParamConfig.__subclasses__())] | RawFileConfig
    ] = Field("Set of files to change on tag")


class ProvisionJob(BaseModel):
    """Job definition for a tag provisioning job."""

    tag_module: TagModule = Field(
        description="Name of tag module supporting target tag type"
    )

    keys: dict[NonNegativeInt, SecretBytes] = Field(
        description="Current set of cryptographic keys (if needed)"
    )
    tag_config: TagConfig = Field(description="Configuration to provision to tag")
