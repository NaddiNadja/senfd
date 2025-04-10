from typing import List

from pydantic import BaseModel


class Error(BaseModel):
    message: str


class ImplementationError(Error):
    pass


class TableOfFiguresError(Error):
    tof_entry_nr: int
    caption: str


class TableError(Error):
    table_nr: int
    caption: str


class FigureError(Error):
    figure_nr: int


class FigureTableRowError(FigureError):
    table_nr: int
    row_idx: int


class FigureTableRowCellError(FigureError):
    table_nr: int
    row_idx: int
    cell_idx: int


class FigureTableMissingError(FigureError):
    pass


class FigureTableMissingRowsError(FigureError):
    pass


class FigureRegexGridMissingError(FigureError):
    pass


class FigureNoGridHeaders(FigureError):
    pass


class FigureNoGridValues(FigureError):
    pass


class TableOfFiguresDescriptionMismatchError(FigureError):
    tof_entry_nr: int
    caption_tof_entry: str
    caption_table_row: str


class FigureDuplicateNumberError(FigureError):
    caption_existing: str
    caption_toinsert: str


class IrregularTableError(FigureError):
    lengths: List[int]


class CannotDetermineCommandRequirement(FigureError):
    pass


class InvalidBitTableEntry(FigureError):
    pass


class MultipleClassifierMatchException(Exception):
    pass


class SkipFigureError(FigureError):
    pass
