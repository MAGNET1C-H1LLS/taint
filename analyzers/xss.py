# analyzers/xss.py
import ast
from typing import Optional
from .base_analyzer import BaseTaintAnalyzer

class XSSAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор XSS:
    - ловит передачу tainted-данных в шаблоны render_template/render_template_string
    - ловит запись/возврат строк с tainted-подстановками
    - учитывает санитайзеры: html.escape, markupsafe.escape (достаточные);
      функции из ineffective_sanitizers помечаются как неэффективные санитайзеры
    """
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)

        # Синк-функции, которые приводят к выводу HTML/текста пользователю
        self.sinks = {
            'render_template', 'render_template_string',
            'flask.render_template', 'flask.render_template_string',
            'make_response', 'Response', 'HttpResponse',
            'wfile.write', 'write', 'send', 'self.wfile.write'
        }

        # Считаем, что render_template с контекстом небезопасен, если значения контекста tainted
        # Также возвращаемые строки (return "...") считаются sink-ом если содержат tainted

    # --- утилиты ---
    def _get_func_simple(self, node: ast.AST) -> str:
        """Wrapper для получения полного имени функции"""
        return self.get_func_name(node)

    def _is_sufficient_sanitizer(self, call_node: ast.Call) -> Optional[bool]:
        """
        Возвращает True если call_node — достаточный санитайзер,
        False если это явно неэффективный санитайзер,
        None если не санитайзер вообще.
        """
        func_name = self.get_func_name(call_node.func)
        if not func_name:
            return None
        # проверяем полное совпадение с базовыми sanitizer-именами
        # self.sanitizers и self.ineffective_sanitizers определены в базовом классе
        if func_name in self.sanitizers:
            return True
        if func_name in self.ineffective_sanitizers:
            return False
        # иногда sanitizer импортирован как html.escape или markupsafe.escape
        # базовый класс может содержать 'html.escape' — выше обработано
        return None

    def _expr_has_sufficient_sanitizer_wrapping(self, node: ast.AST) -> Optional[bool]:
        """
        Проверяет, является ли node вызовом вида sanitizer(...) и возвращает
        True/False/None как в _is_sufficient_sanitizer.
        """
        if isinstance(node, ast.Call):
            res = self._is_sufficient_sanitizer(node)
            if res is not None:
                return res
        return None

    def _expr_contains_taint(self, node: ast.AST) -> bool:
        """
        Использует базовую is_tainted + резолв assignments для определения,
        содержит ли выражение tainted-данные.
        """
        if node is None:
            return False
        try:
            if self.is_tainted(node):
                return True
        except Exception:
            pass

        # Если Name — попробуем резолвить assignment и проверить
        if isinstance(node, ast.Name):
            assigned = self.get_assignment(node.id)
            if assigned is not None:
                return self._expr_contains_taint(assigned)
            return False

        # для f-strings / JoinedStr
        if isinstance(node, ast.JoinedStr):
            for val in node.values:
                if isinstance(val, ast.FormattedValue):
                    if self._expr_contains_taint(val.value):
                        return True
                else:
                    # literal part - skip
                    continue
            return False

        # для BinOp (concat, %), Call(.format), Subscript, Attribute — рекурсивно
        for child in ast.iter_child_nodes(node):
            if self._expr_contains_taint(child):
                return True
        return False

    def _report_xss(self, lineno: int, message: str):
        self.add_finding(f"XSS: {message}", lineno)

    # --- анализ вызовов (render_template, make_response, Response(...)) ---
    def analyze_vulnerability(self, node: ast.Call):
        """
        Проверяем вызовы функций: если это sink и туда попадают tainted данные без
        достаточного санитайзера — сообщаем.
        """
        func_name = self._get_func_simple(node.func)
        if not func_name:
            return

        # проверим, является ли вызов sink'ом
        if not any(sink in func_name for sink in self.sinks):
            return

        # 1) render_template / render_template_string:
        #    - позиционные аргументы: первый аргумент — шаблон/строка
        #    - именованные аргументы — context: values могут быть tainted
        if any(s in func_name for s in ('render_template', 'render_template_string')):
            # проверяем позиционный первый аргумент (шаблон/строка)
            if len(node.args) >= 1:
                tmpl = node.args[0]
                # если шаблон сформирован с taint (f-string/concat/format) -> vuln
                if self._expr_contains_taint(tmpl):
                    # но если этот tmpl - вызов sanitizer(...) — примем как безопасный
                    sres = self._expr_has_sufficient_sanitizer_wrapping(tmpl)
                    if sres is True:
                        return
                    if sres is False:
                        self._report_xss(node.lineno, f"Использован неэффективный санитайзер при формировании шаблона в {func_name}")
                        return
                    self._report_xss(node.lineno, f"Передача заражённого шаблона/строки в {func_name}")
                    return

            # проверяем values в контексте (keywords)
            for kw in getattr(node, "keywords", ()):
                if self._expr_contains_taint(kw.value):
                    # если value — вызов sanitizer -> check
                    if isinstance(kw.value, ast.Call):
                        sres = self._expr_has_sufficient_sanitizer_wrapping(kw.value)
                        if sres is True:
                            continue  # безопасно
                        if sres is False:
                            self._report_xss(node.lineno, f"Неэффективный санитайзер для контекста '{kw.arg}' при вызове {func_name}")
                            continue
                    self._report_xss(node.lineno, f"В контекст шаблона '{kw.arg}' передаются заражённые данные в {func_name}")
            return

        # 2) make_response / Response / HttpResponse / write
        #    если их аргументы содержат tainted -> vuln (с аналогичной проверкой санитайзера)
        for arg in node.args:
            if self._expr_contains_taint(arg):
                if isinstance(arg, ast.Call):
                    sres = self._expr_has_sufficient_sanitizer_wrapping(arg)
                    if sres is True:
                        continue
                    if sres is False:
                        self._report_xss(node.lineno, f"Неэффективный санитайзер при формировании ответа в {func_name}")
                        return
                self._report_xss(node.lineno, f"В {func_name} передаются заражённые данные, которые могут привести к XSS")
                return

        for kw in getattr(node, "keywords", ()):
            if self._expr_contains_taint(kw.value):
                if isinstance(kw.value, ast.Call):
                    sres = self._expr_has_sufficient_sanitizer_wrapping(kw.value)
                    if sres is True:
                        continue
                    if sres is False:
                        self._report_xss(node.lineno, f"Неэффективный санитайзер в {func_name} для ключа {kw.arg}")
                        return
                self._report_xss(node.lineno, f"В {func_name} передаются заражённые данные в ключе {kw.arg}")
                return

    # --- анализ операторов return (return "<html>" + user) ---
    def visit_Return(self, node: ast.Return):
        """
        Если return возвращает строку/шаблон, который включает tainted-данные -> XSS.
        Примеры:
           return "<b>" + user
           return f"<p>{user}</p>"
           return "..." .format(user)
        """
        value = node.value
        if value is None:
            return

        # если выражение содержит taint
        if self._expr_contains_taint(value):
            # если выражение обёрнуто в sanitizer call -> возможно безопасно
            if isinstance(value, ast.Call):
                sres = self._expr_has_sufficient_sanitizer_wrapping(value)
                if sres is True:
                    return
                if sres is False:
                    self._report_xss(node.lineno, "Return: неэффективный санитайзер при формировании возвращаемого HTML")
                    return

            # если это Name — резолвим присвоение и проверим, не было ли оно санитайзировано
            if isinstance(value, ast.Name):
                assigned = self.get_assignment(value.id)
                if assigned is not None:
                    # если assigned — вызов sanitizer -> проверим
                    if isinstance(assigned, ast.Call):
                        sres = self._expr_has_sufficient_sanitizer_wrapping(assigned)
                        if sres is True:
                            return
                        if sres is False:
                            self._report_xss(node.lineno, f"Return: переменная {value.id} обработана неэффективным санитайзером")
                            return
                # иначе — просто tainted variable returned
                self._report_xss(node.lineno, f"Return: возвращается заражённая переменная '{value.id}', возможен XSS")
                return

            # общий случай: tainted в выражении -> warn
            self._report_xss(node.lineno, "Return: возвращается строка/шаблон, содержащая заражённые данные -> потенциальный XSS")
            return

        # если нет taint — ничего
        return
