"""Follow a growing log file, like ``tail -F``.

The follower keeps the file open, so after a rename-style rotation it can drain
whatever the server still wrote to the old file before switching to the new
one. Truncation (``copytruncate``) is detected when the file shrinks below the
read offset, and reading restarts at the beginning.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import BinaryIO

from argus.ingest.reader import DEFAULT_MAX_LINE, SNIPPET_CHARS

_CHUNK = 65536


class Follower:
    def __init__(
        self,
        path: Path,
        *,
        from_start: bool = False,
        poll: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
        max_line: int = DEFAULT_MAX_LINE,
    ) -> None:
        self.path = path
        self.poll = poll
        self.max_line = max_line
        self._sleep = sleep
        self._seek_end = not from_start
        self._handle: BinaryIO | None = None
        self._buffer = b""
        self._skipping = False

    def lines(self, stop: Callable[[], bool] = lambda: False) -> Iterator[tuple[str, bool]]:
        """Yield ``(text, too_long)`` for each complete line until ``stop()`` is true."""
        try:
            while True:
                if self._handle is None:
                    self._open()
                if self._handle is not None:
                    data = self._handle.read(_CHUNK)
                    if data:
                        yield from self._split(data)
                        continue
                    yield from self._check_rotation()
                if stop():
                    return
                self._sleep(self.poll)
        finally:
            if self._handle is not None:
                self._handle.close()
                self._handle = None

    def _open(self) -> None:
        try:
            handle = self.path.open("rb")
        except FileNotFoundError:
            # A file that appears later is new: read it from the beginning.
            self._seek_end = False
            return
        if self._seek_end:
            handle.seek(0, os.SEEK_END)
            self._seek_end = False
        self._handle = handle

    def _check_rotation(self) -> Iterator[tuple[str, bool]]:
        assert self._handle is not None
        try:
            current = self.path.stat()
        except FileNotFoundError:
            return
        opened = os.fstat(self._handle.fileno())
        if (current.st_ino, current.st_dev) != (opened.st_ino, opened.st_dev):
            yield from self._split(self._handle.read())
            if self._buffer:
                yield from self._emit(self._buffer)
            self._handle.close()
            self._handle = None
            self._buffer = b""
            self._skipping = False
        elif current.st_size < self._handle.tell():
            self._handle.seek(0)
            self._buffer = b""
            self._skipping = False

    def _split(self, data: bytes) -> Iterator[tuple[str, bool]]:
        self._buffer += data
        *complete, self._buffer = self._buffer.split(b"\n")
        for raw in complete:
            if self._skipping:
                self._skipping = False
                continue
            yield from self._emit(raw)
        if len(self._buffer) > self.max_line and not self._skipping:
            yield self._buffer[:SNIPPET_CHARS].decode("utf-8", "replace"), True
            self._buffer = b""
            self._skipping = True
        elif self._skipping:
            self._buffer = b""

    def _emit(self, raw: bytes) -> Iterator[tuple[str, bool]]:
        if len(raw) > self.max_line:
            yield raw[:SNIPPET_CHARS].decode("utf-8", "replace"), True
        else:
            yield raw.rstrip(b"\r").decode("utf-8", "replace"), False
