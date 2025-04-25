"""
SkipPatterns

This module provides functionality to load and manage a skip list for figures,
allowing selective exclusion of figures based on configurable patterns.

The skip list is defined in a TOML file and must follow this structure:

    [[skip]]
    regex = "^Decimal.and.Binary.Units$"
    matches = 1
    description = ""

    [[skip]]
    regex = "^Byte, Word, and Dword Relationships$"
    matches = 1
    description = ""

Each entry in the skip list consists of:
    - regex (str): A regular expression pattern used to match figure descriptions.
    - matches (int): The expected number of occurrences of figures matching the pattern.
    - description (str): An optional description explaining why the figure is skipped.

The `SkipPatterns` class reads the skip list from a TOML file, applies the patterns
to figure descriptions, and verifies that the number of matched figures aligns with
the expected count.

Usage:
    skip_patterns = SkipPatterns(list_path=Path("skiplist.toml"), figures=figure_list)
    if skip_patterns.skip_figure(figure):
        print(f"Skipping figure {figure.figure_nr}")

Raises:
    MultipleClassifierMatchException: If the actual number of matched figures
    defined in the SkipElement does not match the expected count.

This module enables flexible and regex-based skipping of figures in structured documents.

"""

import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional

import tomli

from senfd.documents.plain import Figure
from senfd.errors import MultipleClassifierMatchException


class SkipElement(NamedTuple):
    """SkipElement tuple

    Tuple data structure to hold the content of the skip list.

    Args:
        pattern (str): String containing regex pattern to match against a figures
                 description.
        description (str): Text description of skip.
        matches (int): Number of matches that are expected for the regex pattern
                 across all figures.
    """

    pattern: str
    description: str
    matches: int


class SkipPatterns:
    list_path: Optional[Path]
    skip_figures: List[SkipElement]
    figure_map: Dict[int, SkipElement]

    def __init__(self, list_path: Optional[Path], figures: List[Figure]) -> None:
        """
        Initialise the SkipPatterns class.

        Is used to create a map of which figures should be skipped.
        It does also ensure that it matches exactly the number of expected
        figures.

        Args:
            list_path (Optional[Path]): Path to the skip list
            figures (List[Figure]): List of figure objects to match the
            skip list against

        Raises:
            MultipleClassifierMatchException: If the actual number of matched
            figures defined in the SkipElement does not match the expected
            count
        """
        self.list_path = list_path
        self.figure_map = {}
        self.skip_figures: List[SkipElement] = []

        if list_path:
            text = list_path.read_text()
            config = tomli.loads(text)
            patterns = config["skip"]

            for pattern_obj in patterns:
                pattern = pattern_obj["regex"]
                description = str(pattern_obj["description"])
                matches = int(pattern_obj["matches"])

                self.skip_figures.append(
                    SkipElement(
                        pattern=pattern, description=description, matches=matches
                    )
                )

        # Map the figure number to a skip element if there is a match
        # on the regex pattern.
        for fig in figures:
            for skip in self.skip_figures:
                match = re.match(skip.pattern, fig.description)
                if match:
                    self.figure_map[fig.figure_nr] = skip

        # Count number of matches for every skip list element
        counts = Counter(self.figure_map.values())

        for skip, count in counts.items():
            if skip.matches != count:
                raise MultipleClassifierMatchException(
                    f"The number of matches for skip element {skip} was not as expected: {skip.matches} != {count}"
                )

    def skip_figure(self, figure: Figure) -> SkipElement | None:
        """
        Method that tells if figure should be skipped or not.

        Args:
            figure (Figure)

        Returns:
            SkipElement | None: Returns the skip element related to the
            given figure, or None if the figure is not in the skip list.
        """
        if figure.figure_nr in self.figure_map:
            return self.figure_map[figure.figure_nr]
        return None
