import logging
from enum import StrEnum
from nfc.clf import ContactlessFrontend
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler
import typer

from . import provision

LogLevel = StrEnum("LogLevel", {name: name for name in logging.getLevelNamesMapping().keys()})

app = typer.Typer()
app.add_typer(provision.app, name="provision")


@app.callback()
def configure_app(
    ctx: typer.Context,
    log_level: LogLevel = typer.Option(
        LogLevel.INFO, help="Log level for CLI output", case_sensitive=False
    ),
    reader: str = typer.Option("usb", help="Device name of NFC reader to use"),
):
    ctx.ensure_object(dict)

    logging.basicConfig(
        level=log_level.value,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )

    ctx.obj["clf"] = ContactlessFrontend(reader)
