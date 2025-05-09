from argparse import Namespace
from pathlib import Path
from typing import List, Type

from senfd.documents.base import Converter
from senfd.documents.enriched import FromFigureDocument
from senfd.documents.model import FromEnrichedDocument
from senfd.documents.plain import FromDocx
from senfd.errors import Error

CONVERTERS: List[Type[Converter]] = [FromDocx, FromFigureDocument, FromEnrichedDocument]


def process(input: Path, output: Path, args: Namespace) -> List[Error]:
    all_errors = []

    for converter in CONVERTERS:
        if not converter.is_applicable(input):
            continue

        document, errors = converter.convert(input, args)
        all_errors += errors

        document.to_html_file(output, all_errors)
        json_path = document.to_json_file(output)

        all_errors += process(json_path, output, args)
        break

    return all_errors
