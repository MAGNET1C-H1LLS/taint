import ast
import argparse
from typing import Dict, Set, List, Any, Optional

class TaintAnalyzer(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.tainted_vars: Set[str] = set()
        self.findings: List[Dict] = []
        
        # Расширенные конфигурации анализатора
        self.sources = {
            'input', 'getattr', 'open', 'read', 'get', 'post',
            'request.args.get', 'request.form.get', 'request.cookies.get',
            'request.headers.get', 'request.values.get', 'flask.request.args.get',
            'environ', 'os.environ', 'sys.argv', 'raw_input', 'argv',
            'cgi.FieldStorage', 'cgi.parse', 'cgi.parse_qs',
            'urllib.parse.parse_qs', 'urllib.parse.parse_qsl',
            'werkzeug.datastructures.ImmutableMultiDict.get'
        }
        
        # Расширенные стоки сгруппированы по типам уязвимостей
        self.sinks = {
            'SQLi': {'execute', 'executemany', 'query', 'fetchall', 'cursor.execute', 'executescript'},
            'XSS': {
                'write', 'echo', 'print', 'response.write', 'HttpResponse', 'mark_safe', 'SafeText',
                'render_template_string', 'jinja2.Template.render', 'django.template.Template.render',
                'format', 'replace', 'innerHTML', 'innerText', 'document.write', 'eval',
                'window.location', 'document.cookie', 'setAttribute', 'appendChild', 'insertAdjacentHTML',
                'response.set_cookie', 'flask.Response', 'flask.render_template_string'
            },
            'LogInjection': {'log', 'logging', 'write_log', 'logger.info', 'logger.error', 'logger.warning', 'print'},
            'OpenRedirect': {'redirect', 'forward', 'HttpResponseRedirect', 'send_redirect'},
            'ObjectInjection': {
                'pickle.loads', 'yaml.load', 'marshal.loads', 'json.loads', 'eval', 'exec',
                'pickle.load', 'yaml.safe_load', 'json.load', 'xml.etree.ElementTree.fromstring',
                'xml.dom.minidom.parseString', 'lxml.etree.fromstring', 'lxml.etree.parse',
                'xml.sax.parse', 'xml.sax.parseString', 'cPickle.loads', 'cPickle.load'
            },
            'XXE': {'etree.parse', 'parse', 'parseString', 'xml.dom.minidom.parse', 'lxml.etree.parse'},
            'SSRF': {'urlopen', 'requests.get', 'requests.post', 'openurl', 'httpx.get', 'httpx.post'}
        }
        
        # Санитайзеры
        self.effective_sanitizers = {
            'escape_string': {'SQLi'},
            'html.escape': {'XSS'},
            'repr': {'XSS', 'LogInjection'},
            'json.dumps': {'XSS', 'SQLi'},
            'urllib.parse.quote': {'URL'},
            'base64.b64encode': {'Generic'}
        }
        
        self.ineffective_sanitizers = {
            'replace': {'Generic'},
            'strip': {'Generic'},
            'lower': {'Generic'},
            'upper': {'Generic'},
            'my_custom_escape': {'XSS'}
        }

    def add_finding(self, vuln_type: str, message: str, line: int):
        """Добавляет найденную уязвимость в отчет"""
        self.findings.append({
            'type': vuln_type,
            'message': message,
            'line': line,
            'file': self.filename
        })
        print(f"FOUND: {vuln_type} at line {line}: {message}")

    def visit_Assign(self, node: ast.Assign):
        """Анализирует присваивания"""
        # Проверяем, является ли значение источником
        if self.is_source(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    print(f"DEBUG: Marked {target.id} as tainted (source assignment)")
        
        # Проверяем, является ли значение зараженным
        elif self.is_tainted(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.tainted_vars.add(target.id)
                    print(f"DEBUG: Marked {target.id} as tainted (propagation)")
        
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Анализирует вызовы функций"""
        func_name = self.get_func_name(node.func)
        
        # Проверяем источники
        if self.is_source_call(node):
            if hasattr(node, 'parent') and isinstance(node.parent, ast.Assign):
                for target in node.parent.targets:
                    if isinstance(target, ast.Name):
                        self.tainted_vars.add(target.id)
                        print(f"DEBUG: Marked {target.id} as tainted (source call)")
        
        # Вызываем анализаторы для каждого типа уязвимости
        self.analyze_sql_injection(node)
        self.analyze_xss(node)
        self.analyze_log_injection(node)
        self.analyze_open_redirect(node)
        self.analyze_object_injection(node)
        self.analyze_xxe(node)
        self.analyze_ssrf(node)
        
        # Проверяем санитайзеры
        self.check_sanitizers(node)
        
        self.generic_visit(node)

    def is_source_call(self, node: ast.Call) -> bool:
        """Проверяет, является ли вызов функции источником"""
        func_name = self.get_func_name(node.func)
        
        # Проверяем точное совпадение
        if func_name in self.sources:
            return True
            
        # Проверяем частичное совпадение (например, request.*.get)
        for source_pattern in self.sources:
            if source_pattern in func_name or func_name in source_pattern:
                return True
                
        return False

    def is_source(self, node: ast.AST) -> bool:
        """Проверяет, является ли узел источником"""
        if isinstance(node, ast.Call):
            return self.is_source_call(node)
        return False

    def get_func_name(self, func_node: ast.AST) -> str:
        """Извлекает имя функции из узла"""
        if isinstance(func_node, ast.Name):
            return func_node.id
        elif isinstance(func_node, ast.Attribute):
            if isinstance(func_node.value, ast.Name):
                return f"{func_node.value.id}.{func_node.attr}"
            elif isinstance(func_node.value, ast.Attribute):
                return f"{self.get_func_name(func_node.value)}.{func_node.attr}"
            elif isinstance(func_node.value, ast.Call):
                # Обрабатываем вызовы методов объектов
                return f"{self.get_func_name(func_node.value)}.{func_node.attr}"
        return ""

    def is_tainted(self, node: ast.AST) -> bool:
        """Проверяет, содержит ли узел зараженные данные"""
        if isinstance(node, ast.Name):
            result = node.id in self.tainted_vars
            if result:
                print(f"DEBUG: Variable {node.id} is tainted")
            return result
        elif isinstance(node, ast.Call):
            result = self.is_source_call(node)
            if result:
                print(f"DEBUG: Call {self.get_func_name(node.func)} is a source")
            return result
        elif isinstance(node, ast.BinOp):
            left_tainted = self.is_tainted(node.left)
            right_tainted = self.is_tainted(node.right)
            return left_tainted or right_tainted
        elif isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                result = node.value.id in self.tainted_vars
                if result:
                    print(f"DEBUG: Attribute {node.attr} of {node.value.id} is tainted")
                return result
        elif isinstance(node, ast.Subscript):
            return self.is_tainted(node.value)
        elif isinstance(node, ast.JoinedStr):  # f-strings
            for value in node.values:
                if self.is_tainted(value):
                    return True
            return False
        elif isinstance(node, ast.FormattedValue):  # parts of f-strings
            return self.is_tainted(node.value)
        elif isinstance(node, ast.List) or isinstance(node, ast.Tuple):
            for elt in node.elts:
                if self.is_tainted(elt):
                    return True
            return False
        return False

    def check_sanitizers(self, node: ast.Call):
        """Проверяет использование санитайзеры"""
        func_name = self.get_func_name(node.func)
        
        # Проверяем эффективные санитайзеры
        for sanitizer, vuln_types in self.effective_sanitizers.items():
            if func_name == sanitizer:
                if hasattr(node, 'parent') and isinstance(node.parent, ast.Assign):
                    for target in node.parent.targets:
                        if isinstance(target, ast.Name) and target.id in self.tainted_vars:
                            self.tainted_vars.remove(target.id)
                            print(f"DEBUG: Sanitized {target.id} with {func_name}")
        
        # Проверяем неэффективные санитайзеры
        for sanitizer, vuln_types in self.ineffective_sanitizers.items():
            if func_name == sanitizer:
                print(f"DEBUG: Ineffective sanitizer {func_name} used")

    def analyze_sql_injection(self, node: ast.Call):
        """Анализирует SQL-инъекции"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['SQLi']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'SQLi', 
                            f"SQL-инъекция: зараженные данные в {func_name}", 
                            node.lineno
                        )

    def analyze_xss(self, node: ast.Call):
        """Анализирует XSS уязвимости"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['XSS']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'XSS', 
                            f"XSS уязвимость: зараженные данные в {func_name}", 
                            node.lineno
                        )

    def analyze_log_injection(self, node: ast.Call):
        """Анализирует инъекции в логи"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['LogInjection']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'LogInjection', 
                            f"Инъекция в логи: зараженные данные в {func_name}", 
                            node.lineno
                        )

    def analyze_open_redirect(self, node: ast.Call):
        """Анализирует открытые перенаправления"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['OpenRedirect']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'OpenRedirect', 
                            f"Открытое перенаправление: зараженные данные в {func_name}", 
                            node.lineno
                        )

    def analyze_object_injection(self, node: ast.Call):
        """Анализирует инъекции объектов"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['ObjectInjection']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'ObjectInjection', 
                            f"Инъекция объектов: зараженные данные в {func_name}", 
                            node.lineno
                        )

    def analyze_xxe(self, node: ast.Call):
        """Анализирует XXE уязвимости"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['XXE']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'XXE', 
                            f"XXE уязвимость: зараженные данные в {func_name}", 
                            node.lineno
                        )

    def analyze_ssrf(self, node: ast.Call):
        """Анализирует SSRF уязвимости"""
        func_name = self.get_func_name(node.func)
        for sink in self.sinks['SSRF']:
            if sink in func_name:
                for arg in node.args:
                    if self.is_tainted(arg):
                        self.add_finding(
                            'SSRF', 
                            f"SSRF уязвимость: зараженные данные в {func_name}", 
                            node.lineno
                        )

def parse_args():
    parser = argparse.ArgumentParser(description="Taint analysis for Python code")
    parser.add_argument(
        "-t",
        "--taint",
        nargs=2,
        metavar=("FILE", "OUT"),
        required=True,
        help="Perform taint analysis and output results",
    )
    return parser.parse_args()

def taint_analysis(fpath: str):
    analyzer = TaintAnalyzer(fpath)
    with open(fpath, "r", encoding="utf-8") as f:
        tree_ast = ast.parse(f.read(), filename=fpath)
    
    # Добавляем родительские ссылки для обхода AST
    for node in ast.walk(tree_ast):
        for child in ast.iter_child_nodes(node):
            child.parent = node
    
    analyzer.visit(tree_ast)
    return analyzer.findings

def main():
    args = parse_args()
    findings = taint_analysis(args.taint[0])
    
    print(f"Результаты анализа файла {args.taint[0]}:")
    print("=" * 50)
    
    if not findings:
        print("Уязвимостей не обнаружено")
        return
    
    for finding in findings:
        print(f"Тип: {finding['type']}")
        print(f"Сообщение: {finding['message']}")
        print(f"Строка: {finding['line']}")
        print(f"Файл: {finding['file']}")
        print("-" * 30)

if __name__ == "__main__":
    main()