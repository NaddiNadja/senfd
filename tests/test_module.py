#!/usr/bin/env python3
from pathlib import Path
from argparse import Namespace

import senfd.pipeline


def test_module(tmp_path):
    path_example = Path("example")
    paths = list(path_example.glob("*.docx"))
    assert len(paths) > 0, f"No documents available for testing in path({path_example})"

    for path in paths:
        errors = senfd.pipeline.process(path, tmp_path, Namespace(skip_figures=None))

        # There are are bunch of parsing errors, thus there should be errors
        assert errors
