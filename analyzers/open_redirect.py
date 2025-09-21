# analyzers/open_redirect.py
import ast
from typing import Optional
from .base_analyzer import BaseTaintAnalyzer

class OpenRedirectAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор Open Redirect: ловит передачу tainted URL в redirect / HttpResponseRedirect /
    Location header и т.п.
    """
    def __init__(self, filename: str, tainted_vars=None, assignments=None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        # Считаем sink'ами функции с 'redirect' в имени, Response с Location, HttpResponseRedirect и т.п.
        self.sinks_keywords = ("redirect", "HttpResponseRedirect", "HttpResponsePermanentRedirect", "redirect_to")
        self.location_headers = ("Location", "location")

    def _get_full_name(self, func_node: ast.AST) -> str:
        return self.get_func_name(func_node)

    def _expr_contains_absolute_url_literal(self, node: ast.AST) -> bool:
        """
        Статически проверяем, содержит ли выражение явную ссылку 'http://' или 'https://'
        (например: "http://%s" % host, "https://"+host, f"https://{host}" -> все эти шаблоны поймаем)
        """
        if node is None:
            return False
        # String literal
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            s = node.value.lower()
            return s.startswith("http://") or s.startswith("https://") or "http://" in s or "https://" in s
        # f-string / JoinedStr
        if isinstance(node, ast.JoinedStr):
            # собрать все literal-part строки
            for part in node.values:
                if isinstance(part, ast.Constant) and isinstance(part.value, str):
                    s = part.value.lower()
                    if s.startswith("http://") or s.startswith("https://") or "http://" in s or "https://" in s:
                        return True
        # BinOp concatenation: если любой literal-part содержит http
        if isinstance(node, ast.BinOp):
            try:
                return self._expr_contains_absolute_url_literal(node.left) or self._expr_contains_absolute_url_literal(node.right)
            except Exception:
                return False
        # Calls like "format" with literal receiver
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            # check receiver
            return self._expr_contains_absolute_url_literal(node.func.value)
        # Name -> try to resolve assignment
        if isinstance(node, ast.Name):
            assigned = self.get_assignment(node.id)
            if assigned is not None:
                return self._expr_contains_absolute_url_literal(assigned)
        # fallback: scan child constants
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                s = child.value.lower()
                if "http://" in s or "https://" in s:
                    return True
        return False

    def _expr_is_tainted_or_from_source(self, node: ast.AST) -> bool:
        """
        Обёртка: проверяет, является ли выражение заражённым либо содержит источник.
        Использует уже реализованный Base.is_tainted (который резолвит assignments).
        """
        try:
            if self.is_tainted(node):
                return True
        except Exception:
            pass

        # Для Name — пробуем резолвить assignment
        if isinstance(node, ast.Name):
            assigned = self.get_assignment(node.id)
            if assigned is not None:
                return self._expr_is_tainted_or_from_source(assigned)
            return False

        # Для f-strings / BinOp / Call — пройдёмся по подвыражениям
        for child in ast.iter_child_nodes(node):
            if self._expr_is_tainted_or_from_source(child):
                return True
        return False

    def _report(self, lineno: int, message: str):
        self.add_finding(f"Open Redirect: {message}", lineno)

    def analyze_vulnerability(self, node: ast.Call):
        func_name = self._get_full_name(node.func)
        if not func_name:
            return

        # 1) Прямые вызовы redirect(...) / django.shortcuts.redirect / flask.redirect
        if "redirect" in func_name or "HttpResponseRedirect" in func_name or "HttpResponsePermanentRedirect" in func_name:
            # Обычно первый аргумент — URL
            if node.args:
                target = node.args[0]
                # если target tainted -> vuln
                if self._expr_is_tainted_or_from_source(target):
                    # если формирование явно содержит absolute URL literal -> пометим как high-risk
                    if self._expr_contains_absolute_url_literal(target):
                        self._report(node.lineno, f"редирект на tainted абсолютный URL в вызове {func_name}")
                    else:
                        self._report(node.lineno, f"редирект на tainted URL в вызове {func_name}")
                    return
                # если target — Name и assignment содержит taint -> будет покрыто is_tainted выше
            # также, иногда redirect(url=...) именованный аргумент
            for kw in getattr(node, "keywords", ()):
                if kw.arg in ("url", "location", "to", None):  # None: for **kwargs
                    if self._expr_is_tainted_or_from_source(kw.value):
                        self._report(node.lineno, f"редирект на tainted URL в {func_name} (keyword {kw.arg})")
                        return
            return

        # 2) Response(..., headers={'Location': url}) или Response(status=302, headers=...)
        fn_lower = func_name.lower()
        if "response" in fn_lower or "make_response" in fn_lower:
            # Пара: если первый позиционный аргумент — тело, но headers могут быть во втором/keyword
            # ищем keyword 'headers' или args containing dict with Location key
            for kw in getattr(node, "keywords", ()):
                if kw.arg == "headers":
                    hdrs = kw.value
                    # если это dict, ищем Location key
                    if isinstance(hdrs, ast.Dict):
                        for k_node, v_node in zip(hdrs.keys, hdrs.values):
                            # k_node может быть Constant or Str
                            key_name = None
                            if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                                key_name = k_node.value
                            elif hasattr(k_node, "s"):  # older ast.Str
                                key_name = getattr(k_node, "s", None)
                            if key_name and key_name in self.location_headers:
                                if self._expr_is_tainted_or_from_source(v_node):
                                    self._report(node.lineno, f"Location header формируется из tainted значения при вызове {func_name}")
                                    return
            # также, если args contain a dict
            for a in node.args:
                if isinstance(a, ast.Dict):
                    for k_node, v_node in zip(a.keys, a.values):
                        key_name = None
                        if isinstance(k_node, ast.Constant) and isinstance(k_node.value, str):
                            key_name = k_node.value
                        if key_name and key_name in self.location_headers:
                            if self._expr_is_tainted_or_from_source(v_node):
                                self._report(node.lineno, f"Location header формируется из tainted значения при вызове {func_name}")
                                return
            # Finally, some frameworks accept (body, status, headers) tuple as single arg — complex; skip for now
            return

        # 3) Присвоение headers/response.headers[...] = url  (обрабатывается в visit_Assign below)
        return

    def visit_Assign(self, node: ast.Assign):
        """
        Обрабатываем присвоения вида:
          resp.headers['Location'] = url
          resp.headers.update({'Location': url})
          response.setHeader('Location', url)
        """
        # target может быть Subscript: resp.headers['Location']
        for target in node.targets:
            # Subscript case: resp.headers['Location'] = something
            if isinstance(target, ast.Subscript):
                # check if value is Attribute with attr 'headers'
                if isinstance(target.value, ast.Attribute) and target.value.attr == "headers":
                    # index/key
                    key_node = target.slice if hasattr(target, "slice") else target.slice  # compat
                    # simple constant key?
                    key_val = None
                    if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                        key_val = key_node.value
                    elif isinstance(key_node, ast.Index) and isinstance(key_node.value, ast.Constant) and isinstance(key_node.value.value, str):
                        key_val = key_node.value.value
                    if key_val and key_val in self.location_headers:
                        # value is node.value
                        if self._expr_is_tainted_or_from_source(node.value):
                            self._report(node.lineno, f"Location header устанавливается из tainted значения (resp.headers['{key_val}'] = ...)")
                            return
            # Attribute assignment: resp.location = url (less common) or response.location = ...
            if isinstance(target, ast.Attribute):
                if target.attr.lower() in ("location",):
                    if self._expr_is_tainted_or_from_source(node.value):
                        self._report(node.lineno, f"Устанавливается свойство location из tainted значения ({target.attr})")
                        return

        # fallback: оставим базовую обработку (и обновим assignments map)
        super().visit_Assign(node)
