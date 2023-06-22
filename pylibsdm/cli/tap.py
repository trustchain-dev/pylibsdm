import logging
from typing import Optional

import nfc
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
def validate(
    ctx: typer.Context,
    param_picc_data: Optional[str] = typer.Option(None, help="URI parameter for PICC data"),
    param_enc_data: Optional[str] = typer.Option(None, help="URI parameter for SDMENC data"),
    param_cmac: Optional[str] = typer.Option(None, help="URI parameter for CMAC"),
    file_key: str = typer.Argument(16 * "00", help="Key for decrypting SDM file data (hex)"),
    meta_key: str = typer.Argument(16 * "00", help="Key for decrypting SDM meta data (hex)"),
):
    def _do_validate(tag: nfc.tag.Tag) -> bool:
        validator = ParamValidator(
            file_key,
            meta_key,
            param_picc_data=param_picc_data,
            param_enc_data=param_enc_data,
            param_cmac=param_cmac,
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
