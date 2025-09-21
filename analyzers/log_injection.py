# analyzers/log_injection.py
import ast
from .base_analyzer import BaseTaintAnalyzer
from typing import Optional

class LogInjectionAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор лог-инъекций:
    - ловит передачу tainted-данных в logging.*, logger.*, print()
    - учитывает прямое логирование в файловые объекты через .write() и .writelines()
    - учитывает f-strings, конкатенацию, .format(), % formatting
    - учитывает достаточные и неэффективные санитайзеры
    """
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        # Методы логирования
        self.log_methods = {'debug', 'info', 'warning', 'warn', 'error', 'critical', 'exception', 'log'}
        # Модули / объекты логирования
        self.log_modules = ('logging', 'logger', 'log')
        # Методы файлового объекта
        self.file_methods = {'write', 'writelines'}

    def _get_full_func(self, func_node: ast.AST) -> str:
        return self.get_func_name(func_node)

    def _node_is_string_formatting(self, node: ast.AST) -> bool:
        """Проверяет, является ли node строковым формированием (f-string, +, %, .format())"""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            from ast import Mod, Add
            return isinstance(node.op, (Mod, Add))
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def _expr_contains_taint(self, node: ast.AST) -> bool:
        """Использует базовый is_tainted + проверку assignment"""
        if node is None:
            return False
        if self.is_tainted(node):
            return True

        if isinstance(node, ast.Name):
            assigned = self.get_assignment(node.id)
            if assigned is not None:
                return self._expr_contains_taint(assigned)
            return False

        if isinstance(node, ast.JoinedStr):
            return any(self._expr_contains_taint(v.value) for v in node.values if isinstance(v, ast.FormattedValue))

        if isinstance(node, ast.BinOp):
            return self._expr_contains_taint(node.left) or self._expr_contains_taint(node.right)

        if isinstance(node, ast.Call):
            # .format()
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                for a in node.args:
                    if self._expr_contains_taint(a):
                        return True
                for kw in getattr(node, "keywords", ()):
                    if self._expr_contains_taint(kw.value):
                        return True
                if self._expr_contains_taint(node.func.value):
                    return True
            else:
                for a in node.args:
                    if self._expr_contains_taint(a):
                        return True
                for kw in getattr(node, "keywords", ()):
                    if self._expr_contains_taint(kw.value):
                        return True
            return False

        for child in ast.iter_child_nodes(node):
            if self._expr_contains_taint(child):
                return True
        return False

    def _is_parametrized_logging(self, node: ast.Call) -> bool:
        """Проверяет logger.info("...%s...", var) как безопасное параметризированное логирование"""
        if not node.args:
            return False
        first = node.args[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str) and len(node.args) >= 2:
            return True
        return False

    def analyze_vulnerability(self, node: ast.Call):
        func_name = self._get_full_func(node.func)
        if not func_name:
            return

        # проверяем обычные print/logging/logger
        is_log_call = False
        if func_name == "print":
            is_log_call = True
        else:
            for m in self.log_methods:
                if func_name.endswith("." + m) or func_name == m:
                    is_log_call = True
                    break
            if not is_log_call and any(part in func_name for part in self.log_modules):
                for m in self.log_methods:
                    if func_name.endswith("." + m):
                        is_log_call = True
                        break

        # проверяем write/writelines на файловых объектах
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in self.file_methods:
                is_log_call = True

        if not is_log_call:
            return

        if self._is_parametrized_logging(node):
            return  # считаем безопасным

        # Проверяем аргументы на taint
        for arg in node.args:
            if self._node_is_string_formatting(arg) and self._expr_contains_taint(arg):
                self.add_finding(f"Log Injection: строка с tainted данными логируется через {func_name}", node.lineno)
                return
            if self._expr_contains_taint(arg):
                self.add_finding(f"Log Injection: в {func_name} передаются tainted данные", node.lineno)
                return

        for kw in getattr(node, "keywords", ()):
            if self._expr_contains_taint(kw.value):
                self.add_finding(f"Log Injection: в {func_name} через keyword '{kw.arg}' передаются tainted данные", node.lineno)
                return
