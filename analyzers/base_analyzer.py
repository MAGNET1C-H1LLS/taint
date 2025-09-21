# analyzers/base_analyzer.py
import ast
from typing import Set, List, Dict, Any, Optional

class BaseTaintAnalyzer(ast.NodeVisitor):
    def __init__(self, filename: str, tainted_vars: Optional[Set[str]] = None, assignments: Optional[Dict[str, ast.AST]] = None):
        self.filename = filename
        # Если передали пред-вычисленные — используем, иначе пустые множества
        self.tainted_vars: Set[str] = set(tainted_vars) if tainted_vars else set()
        self.findings: List[Dict[str, Any]] = []
        self.assignments: Dict[str, ast.AST] = dict(assignments) if assignments else {}

        self.sources = {
            'input', 'getattr', 'open', 'read', 'get', 'post',
            # flask/django request forms
            'request.args.get', 'request.form.get', 'request.cookies.get',
            'request.headers.get', 'request.values.get', 'flask.request.args.get',
            # common request attributes and methods
            'request.get_json', 'request.get_json.get', 'request.json',
            'request.data', 'request.get_data', 'request.args', 'request.form',
            # environ / cli
            'environ', 'os.environ', 'sys.argv', 'raw_input', 'argv'
        }


        self.sanitizers = {'escape_string', 'html.escape', 'repr', 'json.dumps'}
        self.ineffective_sanitizers = {'replace', 'strip', 'lower', 'upper'}

    def add_finding(self, message: str, line: int):
        vuln_type = self.__class__.__name__.replace('Analyzer', '')
        self.findings.append({
            'type': vuln_type,
            'message': message,
            'line': line,
            'file': self.filename
        })

    def get_func_name(self, func_node: ast.AST) -> str:
        if isinstance(func_node, ast.Name):
            return func_node.id
        if isinstance(func_node, ast.Attribute):
            value_name = self.get_func_name(func_node.value)
            if value_name:
                return f"{value_name}.{func_node.attr}"
            else:
                return func_node.attr
        if isinstance(func_node, ast.Call):
            return self.get_func_name(func_node.func)
        return ""

    def is_source_call(self, node: ast.Call) -> bool:
        func_name = self.get_func_name(node.func)
        return func_name in self.sources

    def is_tainted(self, node: ast.AST) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.Call):
            if self.is_source_call(node):
                return True
            return any(self.is_tainted(arg) for arg in node.args) or \
                   any(self.is_tainted(kw.value) for kw in getattr(node, "keywords", ()))
        elif isinstance(node, ast.Attribute):
            full_name = self.get_func_name(node)
            if full_name in self.sources:
                return True
            # Пробуем проверять, если value tainted
            if hasattr(node.value, 'id') and node.value.id in self.tainted_vars:
                return True
        elif isinstance(node, ast.BinOp):
            return self.is_tainted(node.left) or self.is_tainted(node.right)
        elif isinstance(node, ast.JoinedStr):
            return any(self.is_tainted(v) for v in node.values)
        elif isinstance(node, ast.FormattedValue):
            return self.is_tainted(node.value)
        return False
    def get_assignment(self, name: str):
        return self.assignments.get(name)

    # keep visit methods simple — analyzers will be used after prepass
    def visit_Assign(self, node: ast.Assign):
        # всё такое — но основная работа сделана в prepass
        # тем не менее обновим локальные структуры (на случай, если меняли AST)
        try:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assignments[target.id] = node.value
        except Exception:
            pass
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # Позволяем дочерним анализаторам делать своё
        try:
            self.analyze_vulnerability(node)
        except NotImplementedError:
            pass
        except Exception as e:
            self.add_finding(f"Ошибка в анализаторе {self.__class__.__name__}: {e}", getattr(node, "lineno", 0))
        self.generic_visit(node)

    def analyze_vulnerability(self, node: ast.Call):
        raise NotImplementedError("Дочерние классы должны реализовать analyze_vulnerability")
