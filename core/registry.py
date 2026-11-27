import importlib
import inspect
import pkgutil

import plugins
from core.plugin import Scanner


def discover() -> dict[str, type[Scanner]]:
    found = {}
    for mod in pkgutil.iter_modules(plugins.__path__):
        module = importlib.import_module(f"plugins.{mod.name}")
        for obj in vars(module).values():
            if (
                inspect.isclass(obj)
                and issubclass(obj, Scanner)
                and obj is not Scanner
                and not inspect.isabstract(obj)
                and getattr(obj, "name", None)
            ):
                found[obj.name] = obj
    return found