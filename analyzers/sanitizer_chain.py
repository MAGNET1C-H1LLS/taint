# analyzers/sanitizer_chain.py
import ast
from .base_analyzer import BaseTaintAnalyzer

class SanitizerChainAnalyzer(BaseTaintAnalyzer):
    """
    Анализ цепочек передачи единичных данных с встроенным санитайзером.
    
    Ловит:
    - tainted данные, проходящие через встроенные санитайзеры (sufficient / insufficient)
    - поддерживает f-strings, конкатенацию, % formatting, .format()
    - помечает уязвимость, если санитайзер недостаточен или tainted данные обходят санитайзер
    """
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        # встроенные санитайзеры
        self.sufficient_sanitizers = {'html.escape', 'repr', 'json.dumps'}
        self.insufficient_sanitizers = {'strip', 'replace', 'lower', 'upper'}
    
    def _expr_passed_through_sanitizer(self, node: ast.AST) -> str:
        """
        Проверяет, пропущено ли выражение через санитайзер:
        Возвращает:
            'sufficient' - если санитайзер достаточно безопасный
            'insufficient' - если санитайзер слабый
            None - если не санитайзер
        """
        if isinstance(node, ast.Call):
            func_name = self.get_func_name(node.func)
            if func_name in self.sufficient_sanitizers:
                return 'sufficient'
            if func_name in self.insufficient_sanitizers:
                return 'insufficient'
            # рекурсивно проверяем аргументы
            for arg in node.args:
                result = self._expr_passed_through_sanitizer(arg)
                if result:
                    return result
            for kw in getattr(node, "keywords", ()):
                result = self._expr_passed_through_sanitizer(kw.value)
                if result:
                    return result
        return None

    def _expr_contains_tainted_or_insufficient(self, node: ast.AST) -> bool:
        """
        Проверяет, содержит ли выражение:
        - tainted данные
        - или проходит через недостаточный санитайзер
        """
        if node is None:
            return False
        # если node непосредственно tainted
        if self.is_tainted(node):
            return True
        # проверяем санитайзер
        sanitizer_result = self._expr_passed_through_sanitizer(node)
        if sanitizer_result == 'insufficient':
            return True
        if sanitizer_result == 'sufficient':
            return False
        # рекурсивно проверяем дочерние узлы
        for child in ast.iter_child_nodes(node):
            if self._expr_contains_tainted_or_insufficient(child):
                return True
        return False

    def analyze_vulnerability(self, node: ast.Call):
        """
        Анализирует вызовы функций, которые могут быть sink'ами (например SQL/XSS)
        Для этого анализа просто фиксируем случаи передачи tainted данных через недостаточный санитайзер
        """
        # проверяем все аргументы
        for arg in node.args:
            if self._expr_contains_tainted_or_insufficient(arg):
                self.add_finding(
                    f"Sanitizer Chain: tainted данные проходят через недостаточный санитайзер или напрямую в {self.get_func_name(node.func)}",
                    getattr(node, 'lineno', 0)
                )
                return
        for kw in getattr(node, "keywords", ()):
            if self._expr_contains_tainted_or_insufficient(kw.value):
                self.add_finding(
                    f"Sanitizer Chain: tainted данные через недостаточный санитайзер в {self.get_func_name(node.func)} (keyword {kw.arg})",
                    getattr(node, 'lineno', 0)
                )
                return
