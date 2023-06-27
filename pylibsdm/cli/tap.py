# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import logging
from typing import Optional

import nfc
from pytest import xfail
import typer

from ..backend.validate import ParamValidator

app = typer.Typer()

logger = logging.getLogger(__name__)


@app.callback()
def configure_tap(
    ctx: typer.Context,
):
    """Read SUN messages on token tap"""


@app.command()
def validate_uri_params(
    ctx: typer.Context,
    param_picc_data: Optional[str] = typer.Option(
        None, help="URI parameter for PICC data"
    ),
    param_enc_data: Optional[str] = typer.Option(
        None, help="URI parameter for SDMENC data"
    ),
    param_cmac: Optional[str] = typer.Option(None, help="URI parameter for CMAC"),
    param_cmac_input: Optional[str] = typer.Option(
        None, help="URI parameter to calculate CMAC from"
    ),
    file_key: str = typer.Argument(
        16 * "00", help="Key for decrypting SDM file data (hex)"
    ),
    meta_key: str = typer.Argument(
        16 * "00", help="Key for decrypting SDM meta data (hex)"
    ),
):
    """Validate the URI read from tag via NDEF by reading its query parameters"""

    def _do_validate(tag: nfc.tag.Tag) -> bool:
        validator = ParamValidator(
            file_key,
            meta_key,
            param_picc_data=param_picc_data,
            param_enc_data=param_enc_data,
            param_cmac=param_cmac,
            param_cmac_input=param_cmac_input,
        )
        try:
            validator.parse_ndef(tag)
        except ValueError as exc:
            # FIXME handle correct set of exceptions
            logger.error("Could not find comprehensive URI record: %s", str(exc))
            if not ctx.obj["batch"]:
                raise typer.Exit(code=1)

        # FIXME implement
        if not ctx.obj["batch"]:
            raise typer.Exit(code=0)

        return True

    while True:
        # FIXME add timeout; possibly move elsewhere
        ctx.obj["clf"].connect(
            rdwr={"on-connect": _do_validate, "beep-on-connect": ctx.obj["beep"]}
        )
