import click
import functools
from typing import Callable, Any, TypeVar


T = TypeVar("T")
U = TypeVar("U")


def mk_click_callback(f: Callable[[T], U]) -> Callable[[Any, Any, T], U]:
    @functools.wraps(f)
    def wrapper(_, __, v):
        return f(v)
    return wrapper


# TODO: type it
def deprecated():
    def decorator(f):
        assert isinstance(f, click.core.Command), "decorator is placed above @click.command, therefore decorating a click Command, instead of a bare function"
        command: click.core.Command = f

        command.short_help = "[deprecated]"
        # TODO: uncomment
        # command.hidden = True

        # TODO: construct warning
        deprecation_warning = "ble"

        # TODO: inject warning into execution
        command.help = f"{deprecation_warning}\n\n{command.help}"


        print(command)
        print(type(command))
        print(dir(command))
        return command    
            
    return decorator 
