from pathlib import Path


def _Path_is_relative(p: Path, other: Path) -> bool:
    # TODO: simplify and inline with removal when Python 3.8 is not supported
    try:
        return p.is_relative_to(other)
    # source: https://github.com/python/cpython/blob/3.10/Lib/pathlib.py#L824
    except AttributeError:  # in Python 3.8
        try:
            p.relative_to(*other)
        except ValueError:
            return False
        else:
            return True
