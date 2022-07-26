import typer

# TODO: turn completion to True when implementing completion and somehow merge it with click
app = typer.Typer(hidden=True, add_completion=False)


@app.callback()
def utility_callback():
    """
    Former internal scripts outsourced for the greater good.
    """
    pass


@app.command()
def acquire_secret(prefix: str = typer.Option(""),
                   postfix: str = typer.Option("")):
    """
    The format is $Prefix$Secret$Postfix.

    Given prefix="ble", postfix="zog" and user inputs "fuj"
    the output will be "blefujzog".
    """
    secret = typer.prompt("Enter the value for the secret above")

    print(prefix + secret + postfix)
