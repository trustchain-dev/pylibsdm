# SPDX-FileCopyrightText: © 2023 Dominik George <nik@velocitux.com>
#
# SPDX-License-Identifier: LGPL-2.0-or-later

import logging
from enum import StrEnum
from nfc.clf import ContactlessFrontend
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler
import typer

from . import provision
from . import tap

LogLevel = StrEnum(
    "LogLevel", {name: name for name in logging.getLevelNamesMapping().keys()}
)

app = typer.Typer()
app.add_typer(provision.app, name="provision")
app.add_typer(tap.app, name="tap")


@app.callback()
def configure_app(
    ctx: typer.Context,
    log_level: LogLevel = typer.Option(
        LogLevel.INFO, help="Log level for CLI output", case_sensitive=False
    ),
    reader: str = typer.Option("usb", help="Device name of NFC reader to use"),
    batch: bool = typer.Option(False, help="Batch operation in loop"),
    beep: bool = typer.Option(True, help="Beep reader on connect"),
):
    """Handle SUN-capable NFC tags"""
    ctx.ensure_object(dict)

    logging.basicConfig(
        level=log_level.value,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )

    ctx.obj["clf"] = ContactlessFrontend(reader)
    ctx.obj["batch"] = batch
    ctx.obj["beep"] = beep
