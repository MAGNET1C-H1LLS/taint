# analyzers/object_injection.py
import ast
from .base_analyzer import BaseTaintAnalyzer

class ObjectInjectionAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор Object Injection / Unsafe Deserialization.

    Ловит tainted данные, передаваемые в:
        - pickle.loads, pickle.load
        - yaml.load (но не safe_load)
        - marshal.loads
        - shelve.open / shelve.load
    """
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        # небезопасные sinks
        self.sinks = {
            'pickle.loads', 'pickle.load',
            'yaml.load', 'marshal.loads', 'shelve.open', 'shelve.load'
        }
        # безопасные yaml загрузчики
        self.safe_yaml_loaders = {'yaml.safe_load'}

    def analyze_vulnerability(self, node: ast.Call):
        func_name = self.get_func_name(node.func)
        if not func_name:
            return

        # если безопасный yaml loader — игнорируем
        if func_name in self.safe_yaml_loaders:
            return

        # проверяем, является ли вызов sink
        if func_name in self.sinks:
            # проверка позиционных аргументов
            for arg in node.args:
                if self.is_tainted(arg):
                    self.add_finding(
                        f"Object Injection: tainted данные передаются в {func_name}",
                        node.lineno
                    )
                    return
            # проверка keyword-аргументов
            for kw in getattr(node, "keywords", ()):
                if self.is_tainted(kw.value):
                    self.add_finding(
                        f"Object Injection: tainted данные передаются в {func_name} (keyword {kw.arg})",
                        node.lineno
                    )
                    return
