# analyzers/bulk_data_chain.py
import ast
from .base_analyzer import BaseTaintAnalyzer

class BulkDataChainAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор цепочек массивов / bulk data с propagation taint через циклы и элементы коллекций.
    - Переменные цикла наследуют taint от tainted коллекций.
    - Поддержка f-strings, .format(), конкатенации.
    - Ловит передачу tainted элементов в sink.
    """
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        self.sufficient_sanitizers = {'html.escape', 'repr', 'json.dumps'}
        self.insufficient_sanitizers = {'strip', 'replace', 'lower', 'upper'}

    def _expr_is_tainted_element(self, node: ast.AST) -> bool:
        """Рекурсивная проверка, содержит ли выражение taint"""
        if node is None:
            return False

        if isinstance(node, ast.Name):
            if node.id in self.tainted_vars:
                return True
            assigned = self.get_assignment(node.id)
            if assigned:
                return self._expr_is_tainted_element(assigned)
            return False

        if isinstance(node, ast.Call):
            # taint propagation через объект-атрибут
            if isinstance(node.func, ast.Attribute):
                if self._expr_is_tainted_element(node.func.value):
                    return True
            # проверяем аргументы
            for arg in node.args:
                if self._expr_is_tainted_element(arg):
                    return True
            for kw in getattr(node, "keywords", ()):
                if self._expr_is_tainted_element(kw.value):
                    return True
            func_name = self.get_func_name(node.func)
            if func_name in self.insufficient_sanitizers:
                return True
            if func_name in self.sufficient_sanitizers:
                return False
            return False

        if isinstance(node, ast.Attribute):
            return self._expr_is_tainted_element(node.value)

        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted_element(elt) for elt in node.elts)

        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted_element(k) or self._expr_is_tainted_element(v)
                       for k, v in zip(node.keys, node.values))

        if isinstance(node, ast.JoinedStr):
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    if self._expr_is_tainted_element(v.value):
                        return True
            return False

        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted_element(node.left) or self._expr_is_tainted_element(node.right)

        # fallback: проверяем все дочерние узлы
        for child in ast.iter_child_nodes(node):
            if self._expr_is_tainted_element(child):
                return True

        return False

    def visit_For(self, node: ast.For):
        """
        Если итерируемый объект tainted, переменная цикла наследует taint.
        """
        if self._expr_is_tainted_element(node.iter):
            # Переменная цикла — Name
            if isinstance(node.target, ast.Name):
                self.tainted_vars.add(node.target.id)
            # Переменная цикла — кортеж/список (for a, b in ...)
            elif isinstance(node.target, (ast.Tuple, ast.List)):
                for elt in node.target.elts:
                    if isinstance(elt, ast.Name):
                        self.tainted_vars.add(elt.id)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """
        Присваивание tainted массивов/элементов → переменная помечается tainted.
        """
        if self._expr_is_tainted_element(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
        super().visit_Assign(node)

    def analyze_vulnerability(self, node: ast.Call):
        """
        Проверка передачи массива / bulk data в sink (функцию).
        """
        for arg in node.args:
            if self._expr_is_tainted_element(arg):
                self.add_finding(
                    f"Bulk Data: tainted элементы передаются в {self.get_func_name(node.func)}",
                    getattr(node, 'lineno', 0)
                )
                return
        for kw in getattr(node, "keywords", ()):
            if self._expr_is_tainted_element(kw.value):
                self.add_finding(
                    f"Bulk Data: tainted элементы передаются в {self.get_func_name(node.func)} (keyword {kw.arg})",
                    getattr(node, 'lineno', 0)
                )
                return
