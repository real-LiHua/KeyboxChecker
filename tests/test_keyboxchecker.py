from __future__ import annotations

from keyboxchecker import Error, Keybox


class TestKeybox:
    def test_不存在keybox(self) -> None:
        keybox = Keybox("1000.xml")
        assert keybox.flag & Error.Invalid_File_Path
