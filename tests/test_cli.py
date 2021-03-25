# -*- coding: utf-8 -*-
# pylint: disable=missing-docstring,unused-import,reimported
import pathlib
import sys
import pytest  # type: ignore

import cvrf_util as cli


def test_main_nok_empty(capsys):
    with pytest.raises(SystemExit):
        cli.main([])
    out, err = capsys.readouterr()
    for term in ('file', 'required'):
        assert term in err


def test_main_nok_int(capsys):
    with pytest.raises(TypeError):
        cli.main(42)
    out, err = capsys.readouterr()
    assert not out
    assert not err


def test_main_nok_ints(capsys):
    sequence_of_ints = [1, 2, 3]
    with pytest.raises(TypeError):
        cli.main(sequence_of_ints)
    out, err = capsys.readouterr()
    assert not out
    assert not err


def test_main_nok_non_existing_folder(capsys):
    nef = non_existing_folder_path = 'folder_does_not_exist'
    a_name = 'my_script'
    assert pathlib.Path(nef).is_dir() is False, f"Unexpected folder {nef} exists which breaks this test"
    message = '%s: I/O error: "%s" does not exist' % (a_name, nef)
    sys.argv.append('--file')
    sys.argv.append(nef)
    with pytest.raises(SystemExit, match=message):
        cli.main(a_name)
    out, err = capsys.readouterr()
