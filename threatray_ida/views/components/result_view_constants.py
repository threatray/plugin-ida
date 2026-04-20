# this file contains text constants which are used in the result view of different features
FILTER_TEXT: str = 'Filter: '
CONTEXT_MENU_COPY_TEXT: str = 'Copy'
CONTEXT_MENU_COPY_LINK_TEXT: str = 'Copy link'
JUMP_TO_FUNCTION_TEXT: str = 'Jump to function'
TOOLTIP_JUMP_TO_FUNCTION_TEXT: str = 'Double-click to jump to the view of the given function'
EXPORT_TABLE_TEXT: str = 'Export table to CSV file'
EXPORT_TABLE_CAPTION_TEXT: str = 'Save table to'
EXPORT_TABLE_FILTER_TEXT: str = 'Text CSV (*csv)'


def get_context_menu_function_retrohunt_text(has_several_rows_selected: bool) -> str:
    return (f"Retrohunt Functions with query function{'s' if has_several_rows_selected else ''} of selected "
            f"row{'s' if has_several_rows_selected else ''}")


def get_context_menu_cluster_against_text(has_several_rows_selected: bool) -> str:
    return (f"Cluster against file{'s' if has_several_rows_selected else ''} of "
            f"selected row{'s' if has_several_rows_selected else ''}")
