import json
from pathlib import Path

import pytest

FIX = Path(__file__).parent / "fixtures"


def load_json(*parts: str):
    return json.loads(FIX.joinpath(*parts).read_text())


def load_text(*parts: str) -> str:
    return FIX.joinpath(*parts).read_text()


@pytest.fixture
def fx():
    return load_json


@pytest.fixture
def fxt():
    return load_text


@pytest.fixture
def catalog():
    from pch.collectors.ado.task_catalog import TaskCatalog

    cat = TaskCatalog.from_payload(load_json("ado", "tasks.json"))
    cat.add_task_groups(load_json("ado", "taskgroups.json"))
    return cat
