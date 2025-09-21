# utils/taint_prepass.py
import ast
from typing import Dict, Set, Optional

class TaintPrepass(ast.NodeVisitor):
    """
    Собирает все присвоения (assignments) в видимой области модуля/функций
    и итеративно распространяет taint метки от источников через присвоения.
    В результате предоставляет:
      - assignments: Dict[str, ast.AST]  (последнее присвоение для имени)
      - tainted_vars: Set[str]
    """
    def __init__(self):
        # последнее присвоение имени -> AST выражение
        self.assignments: Dict[str, ast.AST] = {}
        # переменные, помеченные как tainted
        self.tainted_vars: Set[str] = set()
        # список всех присвоений (имя -> list of nodes) для итеративного анализа
        self._all_assignments = []

    def visit_Assign(self, node: ast.Assign):
        # сохраняем последнее присвоение для каждого target-Name
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.assignments[target.id] = node.value
                self._all_assignments.append((target.id, node.value, node.lineno if hasattr(node, "lineno") else 0))
        # Также пометим как tainted, если RHS — непосредственный источник (Call)
        # Реализуем простую проверку: call.func имя содержит "request." или is builtin input/... (это базовый heuristic)
        if isinstance(node.value, ast.Call):
            func_name = self._get_func_name(node.value.func)
            if func_name and self._is_likely_source_name(func_name):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        # обработаем x += ... как присвоение
        target = node.target
        if isinstance(target, ast.Name):
            self.assignments[target.id] = ast.BinOp(left=ast.Name(id=target.id, ctx=ast.Load()), op=node.op, right=node.value)
            self._all_assignments.append((target.id, self.assignments[target.id], node.lineno if hasattr(node, "lineno") else 0))
        self.generic_visit(node)

    def _get_func_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            parent = self._get_func_name(node.value)
            if parent:
                return f"{parent}.{node.attr}"
            return node.attr
        if isinstance(node, ast.Call):
            return self._get_func_name(node.func)
        return ""

    def _is_likely_source_name(self, func_name: str) -> bool:
        # простая эвристика источников — расширяй при необходимости
        src_patterns = (
            "request.", "flask.request", "get_json", "request.get_json",
            "input", "raw_input", "sys.argv", "os.environ", "environ", "cgi.FieldStorage"
        )
        for p in src_patterns:
            if p in func_name:
                return True
        return False

    def _node_contains_source(self, node: Optional[ast.AST]) -> bool:
        """Рекурсивно проверяет, есть ли в node непосредственный источник (Call с request.* и т.п.)"""
        if node is None:
            return False
        # BFS/DFS по дереву
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                fn = self._get_func_name(child.func)
                if fn and self._is_likely_source_name(fn):
                    return True
            if isinstance(child, ast.Attribute):
                fn = self._get_func_name(child)
                if fn and self._is_likely_source_name(fn):
                    return True
        return False

    def compute_taints(self):
        """
        Итеративно распространяет taint метки по присвоениям:
        если RHS содержит источник или содержит уже tainted переменную -> помечаем LHS.
        Повторяем до стабилизации.
        """
        changed = True
        while changed:
            changed = False
            for name, expr, _lineno in list(self._all_assignments):
                if name in self.tainted_vars:
                    continue
                # если RHS содержит источник — taint
                if self._node_contains_source(expr):
                    self.tainted_vars.add(name)
                    changed = True
                    continue
                # если RHS использует имена, и хотя бы одно имя помечено tainted -> propagate
                uses = [n.id for n in ast.walk(expr) if isinstance(n, ast.Name)]
                for u in uses:
                    if u in self.tainted_vars:
                        self.tainted_vars.add(name)
                        changed = True
                        break
        # готово

    def run(self, tree: ast.AST):
        self.visit(tree)
        self.compute_taints()
        return self.assignments, self.tainted_vars
