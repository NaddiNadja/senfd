"""
Documents
=========

The following classes model documents at different stages of parsing / processing a
specification document from a raw extract into something semantically rich.
"""

import importlib.resources as pkg_resources
import json
from abc import ABC, abstractmethod
from argparse import Namespace
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Optional, Tuple

from jinja2 import Environment, PackageLoader, select_autoescape
from pydantic import BaseModel, Field

import senfd.schemas
import senfd.tables
import senfd.utils
from senfd.errors import Error

TRANSLATION_TABLE: Dict[int, str] = str.maketrans(
    {
        "–": "-",  # en dash
        "—": "-",  # em dash
        "‘": "'",  # left single quotation mark
        "’": "'",  # right single quotation mark
        "“": '"',  # left double quotation mark
        "”": '"',  # right double quotation mark
        "…": "...",  # ellipsis
        "é": "e",  # e with acute accent
        "á": "a",  # a with acute accent
        "í": "i",  # i with acute accent
        "ó": "o",  # o with acute accent
        "ú": "u",  # u with acute accent
        "ü": "u",  # u with diaeresis
        "ñ": "n",  # n with tilde
        "ç": "c",  # c with cedilla
    }
)


def to_file(content: str, filename: str, path: Optional[Path] = None):
    """
    Writes 'content' to a file and returns the file path.

    Args:
        content (str): The content to write.
        filename (str): The file name.
        path (str, optional): The directory or file path. Defaults to None.

    Returns:
        str: The path to the written file.

    Behavior:
        - Uses the current working directory if 'path' is not provided.
        - Uses 'filename' within the provided directory if 'path' is a directory.
        - Uses 'path' directly if it is a full file path.
    """
    if path is None:
        path = Path.cwd() / filename
    if path.is_dir():
        path = path / filename

    path.write_text(content)

    return path


def strip_all_suffixes(file_path):
    p = Path(file_path)
    while p.suffix:
        p = p.with_suffix("")
    return p.name


class DocumentMeta(BaseModel):
    version: str = senfd.__version__
    stem: str = Field(default_factory=str)


class Document(BaseModel):
    """
    Base document - providing functionality for describing and persisting documents

    The intent here is that all Documents should be representable as JSON and HTML
    """

    SUFFIX_JSON: ClassVar[str] = ".document.json"
    SUFFIX_HTML: ClassVar[str] = ".document.html"

    FILENAME_SCHEMA: ClassVar[str] = "document.schema.json"
    FILENAME_HTML_TEMPLATE: ClassVar[str] = "document.html.jinja2"

    meta: DocumentMeta = Field(default_factory=DocumentMeta)

    @classmethod
    def schema_filename(cls) -> str:
        return cls.FILENAME_SCHEMA

    @classmethod
    def to_schema_file(cls, path: Optional[Path] = None) -> Path:
        """Writes the document JSON schema to file at the given 'path'"""

        return to_file(
            json.dumps(cls.model_json_schema(), indent=4),
            cls.schema_filename(),
            path,
        )

    @classmethod
    def schema_static(cls) -> Dict[str, Any]:
        """Returns the content of the associated JSON schema-file"""

        with pkg_resources.open_text(senfd.schemas, cls.FILENAME_SCHEMA) as content:
            return json.load(content)

    def json_filename(self) -> str:
        return f"{self.meta.stem}{self.SUFFIX_JSON}"

    def to_json(self) -> str:
        """Returns the document as a JSON-formatted string"""

        return self.model_dump_json()

    def to_json_file(self, path: Optional[Path] = None) -> Path:
        """Writes the document, formatted as JSON, to file at the given 'path'"""

        return to_file(self.to_json(), self.json_filename(), path)

    def html_filename(self) -> str:
        return f"{self.meta.stem}{self.SUFFIX_HTML}"

    def to_html(self, errors: List[Error] = []) -> str:
        """Returns the document as a HTML-formatted string"""

        env = Environment(
            loader=PackageLoader("senfd", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        env.filters["snake_to_pascal"] = senfd.utils.snake_to_pascal
        env.filters["pascal_to_snake"] = senfd.utils.pascal_to_snake
        template = env.get_template(self.FILENAME_HTML_TEMPLATE)

        figure_errors: Dict[int, List[Error]] = {}
        for error in errors:
            if not hasattr(error, "figure_nr"):
                continue

            if error.figure_nr not in figure_errors:
                figure_errors[error.figure_nr] = []
            figure_errors[error.figure_nr].append(error)

        return template.render(document=self.model_dump(), figure_errors=figure_errors)

    def to_html_file(
        self, path: Optional[Path] = None, errors: List[Error] = []
    ) -> Path:
        """Writes the document to HTML-formatted file"""

        return to_file(self.to_html(errors), self.html_filename(), path)


class Converter(ABC):
    @staticmethod
    @abstractmethod
    def is_applicable(path: Path) -> bool:
        """Check whether the converter is applicable to the given 'path'"""

    @staticmethod
    @abstractmethod
    def convert(path: Path, args: Namespace) -> Tuple[Document, List[Error]]:
        """Convert the given 'path' into a 'Document'"""
