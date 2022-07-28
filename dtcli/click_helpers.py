import functools
import types
from typing import Callable, Any, TypeVar, Optional

import click


T = TypeVar("T")
U = TypeVar("U")


def mk_click_callback(f: Callable[[T], U]) -> Callable[[Any, Any, T], U]:
    @functools.wraps(f)
    def wrapper(_, __, v):
        return f(v)
    return wrapper


# TODO: type the returns
def _deprecated_above(deprecation_warning: str):
    def decorator(f):
        assert isinstance(f, click.core.Command), "decorator is placed above @click.command," \
                                                  " therefore decorating a click Command," \
                                                  " instead of a bare function"
        command: click.core.Command = f

        command.short_help = "[deprecated]"
        command.hidden = True
        command.deprecated = True

        command.help = f"{deprecation_warning}\n{command.help}"
    return decorator


def _deprecated_below(warning_f: Callable[[], None]):
    def decorator(f):
        assert isinstance(f, types.FunctionType), "decorator is placed below @click.command," \
                                                  " therefore decorating a a bare function," \
                                                  " not a registered Click command"

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            warning_f()
            return f(*args, **kwargs)
        return wrapper
    return decorator


def deprecated(alternative: Optional[str], alternative_help: Optional[str] = None):
    """
    This has to happen this way.

    Click decorator registers the function automatically, so I'd need to track where it's registered or something [so
    the acutal function that's run could be decorated], instead I've opted for spawining 2 decorators and just doing
    it the hacky way.
    """
    if alternative:
        alt_text = f"\nPlease consider using {click.style(alternative,fg='bright_cyan')} instead." \
                   f"{' ' + alternative_help.capitalize() + '.' if alternative_help else ''}\n"
    else:
        alt_text = ""
    warning = f"{click.style('This function is deprecated', fg='red')}.{alt_text}"
    return (_deprecated_above(warning), _deprecated_below(lambda: click.echo(warning)))


# TODO: type it correctly
def compose_click_decorators_2(a, b) -> "decorator":  # noqa: F821
    def wrapper(f):
        return a(b(f))
    return wrapper
