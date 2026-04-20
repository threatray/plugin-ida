from dataclasses import dataclass
from typing import Generic, Tuple, TypeVar, Union

T = TypeVar('T')


@dataclass
class TableRowData(Generic[T]):
    """ Represents a row of data for display in a table.
     Attributes:
        model: The underlying data model for the row.
        display_values: A tuple of values to be displayed in the table.
    """
    model: T
    display_values: Tuple[Union[str, int], ...]
