# analyzers/sql_injection.py
import ast
from .base_analyzer import BaseTaintAnalyzer

class SQLInjectionAnalyzer(BaseTaintAnalyzer):
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        self.sinks = {
            'execute', 'executemany', 'executescript', 'query',
            'cursor.execute', 'cursor.executemany', 'connection.execute'
        }

    def _node_is_string_formatting(self, node: ast.AST) -> bool:
        import ast as _ast
        if isinstance(node, _ast.JoinedStr):
            return True
        if isinstance(node, _ast.BinOp):
            from ast import Mod, Add
            if isinstance(node.op, (Mod, Add)):
                return True
        if isinstance(node, _ast.Call):
            if isinstance(node.func, _ast.Attribute) and node.func.attr == "format":
                return True
        return False

    def _expr_contains_taint_or_source(self, node: ast.AST) -> bool:
        # используем базовый is_tainted (который резолвит assignments) и дополнительную проверку на source в assignment
        if node is None:
            return False
        try:
            if self.is_tainted(node):
                return True
        except Exception:
            pass

        # если это Name — попробуем резолвить assignment и проверить RHS на source
        if isinstance(node, ast.Name):
            assigned = self.get_assignment(node.id)
            if assigned is not None:
                # если RHS содержит вызов request.* или похожий источник — считаем tainted
                # обойдём дерево RHS на наличие Call с именем request.*
                for child in ast.walk(assigned):
                    if isinstance(child, ast.Call):
                        fn = self.get_func_name(child.func)
                        if fn and any(p in fn for p in ("request.", "get_json", "flask.request")):
                            return True
                # также рекурсивно проверим RHS на taint (через is_tainted)
                return self.is_tainted(assigned)
            return False

        # для выражений: проверим подузлы на taint
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.tainted_vars:
                return True
            if isinstance(child, ast.Call):
                fn = self.get_func_name(child.func)
                if fn and any(p in fn for p in ("request.", "get_json", "flask.request")):
                    return True
        return False

    def analyze_vulnerability(self, node: ast.Call):
        func_name = self.get_func_name(node.func)
        if not any(sink in func_name for sink in self.sinks):
            return

        # single/multi-arg handling
        if len(node.args) >= 1:
            first = node.args[0]
            # если передали SQL и параметры — но SQL сформирован заранее (format/concat) => vuln
            if len(node.args) >= 2:
                if (self._node_is_string_formatting(first) or self._expr_contains_taint_or_source(first)):
                    self.add_finding(f"SQL-инъекция: формирование SQL посредством форматирования/конкатенации в {func_name}", node.lineno)
                    return
                return

            # single arg
            if isinstance(first, ast.Name):
                assigned = self.get_assignment(first.id)
                if assigned is not None:
                    if (self._node_is_string_formatting(assigned) or self._expr_contains_taint_or_source(assigned)):
                        self.add_finding(f"SQL-инъекция: переменная {first.id} содержит сформированный/заражённый SQL перед вызовом {func_name}", node.lineno)
                        return
                # fallback: если сама переменная tainted
                if first.id in self.tainted_vars:
                    self.add_finding(f"SQL-инъекция: в {func_name} передаются заражённые данные (переменная {first.id})", node.lineno)
                    return

            else:
                # выражение сразу
                if (self._node_is_string_formatting(first) or self._expr_contains_taint_or_source(first)):
                    self.add_finding(f"SQL-инъекция: query формируется через форматирование/concat/f-string в {func_name}", node.lineno)
                    return
