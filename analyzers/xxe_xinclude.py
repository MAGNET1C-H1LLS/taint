# analyzers/xxe_xinclude.py
import ast
from typing import Optional, Dict
from analyzers.base_analyzer import BaseTaintAnalyzer

class XXEXIncludeAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор для сценариев XInclude + XXE (включение внешних ресурсов через XInclude),
    которые могут обойти блокировку DOCTYPE/ENTITY и привести к чтению/запросам по сети.

    Правила (эвристика):
    - detect tree.xinclude() вызовы: если дерево получено от tainted источника -> report
    - detect etree.XInclude() / .xinclude usage or explicit xi:include strings with http(s) hrefs
    - detect parser constructors with flags that allow network/external entities (no_network False, resolve_entities True, load_dtd True, huge_tree True)
    - if parser + xinclude usage + tainted data -> high confidence finding
    """
    def __init__(self, filename: str, tainted_vars: Optional[set] = None, assignments: Optional[Dict[str, ast.AST]] = None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)

        # parser constructor names to check (similar to other XXE analyzers)
        self.parser_constructors = {
            'lxml.etree.XMLParser', 'xml.etree.ElementTree.XMLParser',
            'xml.sax.make_parser', 'xml.parsers.expat.ParserCreate',
        }

        # keywords that, if set to permissive values, increase risk
        self.unsafe_parser_kwargs = {'no_network', 'resolve_entities', 'load_dtd', 'huge_tree', 'recover'}

        # xml functions considered parse entrypoints
        self.xml_parse_funcs = {
            'xml.etree.ElementTree.parse', 'xml.etree.ElementTree.fromstring',
            'xml.etree.fromstring', 'lxml.etree.parse', 'lxml.etree.fromstring',
            'xml.dom.minidom.parseString', 'xml.dom.minidom.parse',
            'etree.parse', 'etree.fromstring'
        }

        # safe prefixes (defusedxml)
        self.safe_prefixes = ('defusedxml.',)

    def _is_safe_call(self, func_name: str) -> bool:
        if not func_name:
            return False
        for p in self.safe_prefixes:
            if func_name.startswith(p):
                return True
        return False

    def _call_is_parser_constructor(self, node: ast.Call) -> bool:
        fn = self.get_func_name(node.func)
        if not fn:
            return False
        if fn in self.parser_constructors:
            return True
        base = fn.split('.')[-1]
        for pc in self.parser_constructors:
            if base == pc.split('.')[-1]:
                return True
        return False

    def _parser_has_unsafe_kwargs(self, node: ast.Call) -> bool:
        for kw in getattr(node, "keywords", ()):
            if not kw.arg:
                continue
            if kw.arg in self.unsafe_parser_kwargs:
                # if kw.value is constant True => unsafe; else conservative True
                if isinstance(kw.value, ast.Constant):
                    try:
                        if bool(kw.value.value) is True:
                            return True
                    except Exception:
                        return True
                else:
                    return True
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, bool) and a.value is True:
                return True
        return False

    def _expr_contains_xinclude_literal(self, expr: ast.AST) -> bool:
        """
        Ищет в константах явные <xi:include href="http://..."/> или другие href с http(s).
        Работает с Constant, JoinedStr, BinOp конкатенацией.
        """
        if expr is None:
            return False
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            s = expr.value.lower()
            if '<xi:include' in s or 'xinclude' in s:
                # если есть href с http/https — особенно подозрительно
                if 'http://' in s or 'https://' in s or 'file://' in s:
                    return True
                # если нет href, но есть xi:include — также подозрительно
                return True
            # plain url inside xml literal can indicate remote include
            if 'http://' in s or 'https://' in s:
                return True
            return False
        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    if self._expr_contains_xinclude_literal(v):
                        return True
            return False
        if isinstance(expr, ast.BinOp):
            return self._expr_contains_xinclude_literal(expr.left) or self._expr_contains_xinclude_literal(expr.right)
        if isinstance(expr, ast.Name):
            assigned = self.get_assignment(expr.id)
            if assigned is not None and assigned is not expr:
                return self._expr_contains_xinclude_literal(assigned)
            return False
        if isinstance(expr, ast.Call):
            for a in expr.args:
                if self._expr_contains_xinclude_literal(a):
                    return True
            for kw in getattr(expr, "keywords", ()):
                if self._expr_contains_xinclude_literal(kw.value):
                    return True
            return False
        for child in ast.iter_child_nodes(expr):
            if self._expr_contains_xinclude_literal(child):
                return True
        return False

    def _is_tainted_or_wraps_tainted(self, expr: ast.AST) -> bool:
        # reuse base heuristics similar to other analyzers
        try:
            if self.is_tainted(expr):
                return True
        except Exception:
            pass
        if isinstance(expr, ast.Name):
            assigned = self.get_assignment(expr.id)
            if assigned is not None and assigned is not expr:
                return self._is_tainted_or_wraps_tainted(assigned)
            return False
        if isinstance(expr, ast.Call):
            # open(tainted) => tainted filename
            fname = self.get_func_name(expr.func)
            if fname == 'open' and expr.args:
                return self._is_tainted_or_wraps_tainted(expr.args[0])
            for a in expr.args:
                if self._is_tainted_or_wraps_tainted(a):
                    return True
            for kw in getattr(expr, "keywords", ()):
                if self._is_tainted_or_wraps_tainted(kw.value):
                    return True
            return False
        for child in ast.iter_child_nodes(expr):
            if self._is_tainted_or_wraps_tainted(child):
                return True
        return False

    def analyze_vulnerability(self, node: ast.Call):
        """
        Проверяем:
         - вызовы .xinclude() на объектах, полученных из parse/fromstring/assignments — если источник tainted или литерал содержит xi:include -> report
         - явные etree.XInclude() вызовы / создание XInclude обёрток -> report если tainted или literal href
         - парсер-конструкторы с небезопасными kwargs + дальнейшее использование -> report
        """
        func_name = self.get_func_name(node.func) or ""

        # skip defusedxml
        if self._is_safe_call(func_name):
            return

        # 1) detect direct creation of XInclude handler or usage of XInclude in code
        # e.g. etree.XInclude(), lxml.etree.XInclude()
        if func_name.lower().endswith('xinclude') or '.xinclude' in func_name.lower():
            # if args contain literal remote href or tainted -> warn
            for a in node.args:
                if self._expr_contains_xinclude_literal(a) or self._is_tainted_or_wraps_tainted(a):
                    self.add_finding(
                        f"XXE_XINCLUDE: Используется XInclude '{func_name}' с потенциально внешним href/tainted данными — возможное включение удалённых ресурсов",
                        getattr(node, "lineno", 0)
                    )
                    return

        # 2) detect calls to .xinclude() method on tree objects
        # node.func can be Attribute with attr == 'xinclude'
        if isinstance(node.func, ast.Attribute) and getattr(node.func, 'attr', '') == 'xinclude':
            # want to find where this tree came from: if receiver is Name and has assignment from parse/fromstring or tainted source
            receiver = node.func.value
            # if receiver is Call(...parse...) e.g. etree.parse(...).xinclude()
            if isinstance(receiver, ast.Call):
                # if parse/fromstring was called with tainted data or literal xi href -> warn
                called_name = self.get_func_name(receiver.func)
                if called_name and (called_name in self.xml_parse_funcs or any(called_name.endswith(s.split('.')[-1]) for s in self.xml_parse_funcs)):
                    # check args to parse/fromstring
                    for a in receiver.args:
                        if self._is_tainted_or_wraps_tainted(a) or self._expr_contains_xinclude_literal(a):
                            self.add_finding(
                                f"XXE_XINCLUDE: Вызов parse(...).xinclude() где источник данных ({called_name}) является tainted или содержит XInclude href — возможное включение удалённых ресурсов",
                                getattr(node, "lineno", 0)
                            )
                            return
                    for kw in getattr(receiver, "keywords", ()):
                        if self._is_tainted_or_wraps_tainted(kw.value) or self._expr_contains_xinclude_literal(kw.value):
                            self.add_finding(
                                f"XXE_XINCLUDE: parse(..., parser=...).xinclude() с ненадёжным источником (keyword) — возможный XInclude-атака",
                                getattr(node, "lineno", 0)
                            )
                            return
            # if receiver is Name -> resolve assignment (tree = etree.parse(...); tree.xinclude())
            if isinstance(receiver, ast.Name):
                assigned = self.get_assignment(receiver.id)
                if assigned is not None:
                    # if assigned is Call to parse/fromstring
                    if isinstance(assigned, ast.Call):
                        pname = self.get_func_name(assigned.func)
                        if pname and (pname in self.xml_parse_funcs or any(pname.endswith(s.split('.')[-1]) for s in self.xml_parse_funcs)):
                            # check args of original parse call
                            for a in assigned.args:
                                if self._is_tainted_or_wraps_tainted(a) or self._expr_contains_xinclude_literal(a):
                                    self.add_finding(
                                        f"XXE_XINCLUDE: Метод xinclude() вызывается на дереве, созданном из ненадёжного источника ({pname}) — возможное включение внешних ресурсов",
                                        getattr(node, "lineno", 0)
                                    )
                                    return
                            for kw in getattr(assigned, "keywords", ()):
                                if self._is_tainted_or_wraps_tainted(kw.value) or self._expr_contains_xinclude_literal(kw.value):
                                    self.add_finding(
                                        f"XXE_XINCLUDE: Метод xinclude() вызывается на дереве, где keyword-аргумент источника может быть ненадёжным — возможная XInclude уязвимость",
                                        getattr(node, "lineno", 0)
                                    )
                                    return
                    # assigned could be Name referencing earlier var; try one-level resolve
                    if isinstance(assigned, ast.Name):
                        deeper = self.get_assignment(assigned.id)
                        if isinstance(deeper, ast.Call):
                            pname = self.get_func_name(deeper.func)
                            if pname and (pname in self.xml_parse_funcs or any(pname.endswith(s.split('.')[-1]) for s in self.xml_parse_funcs)):
                                for a in deeper.args:
                                    if self._is_tainted_or_wraps_tainted(a) or self._expr_contains_xinclude_literal(a):
                                        self.add_finding(
                                            f"XXE_XINCLUDE: xinclude() на дереве из ненадёжного источника ({pname}) — возможное включение внешних ресурсов",
                                            getattr(node, "lineno", 0)
                                        )
                                        return

        # 3) parser constructors with unsafe kwargs used together with xinclude or remote hrefs
        if self._call_is_parser_constructor(node) and self._parser_has_unsafe_kwargs(node):
            # conservative: if any xinclude literal appears anywhere in assignments or any tainted var exists => warn
            # quick scan: check assignments for xinclude literals or tainted usage in parse calls
            found_remote_pattern = False
            for name, rhs in self.assignments.items():
                if self._expr_contains_xinclude_literal(rhs):
                    found_remote_pattern = True
                    break
            if found_remote_pattern or self.tainted_vars:
                self.add_finding(
                    f"XXE_XINCLUDE: Создан парсер {self.get_func_name(node.func)} с небезопасными флагами; присутствуют tainted или XInclude-литералы в коде — возможно выполнение внешних включений через XInclude",
                    getattr(node, "lineno", 0)
                )
                return

        # 4) direct parse(...) calls: if data arg contains xinclude literal or tainted and parser kw unsafe -> report
        pname = self.get_func_name(node.func)
        if pname and (pname in self.xml_parse_funcs or any(pname.endswith(s.split('.')[-1]) for s in self.xml_parse_funcs)):
            # if any arg contains xinclude literal -> warn
            for a in node.args:
                if self._expr_contains_xinclude_literal(a):
                    self.add_finding(
                        f"XXE_XINCLUDE: Вызов парсера '{pname}' получает литерал с XInclude, возможное включение внешних ресурсов",
                        getattr(node, "lineno", 0)
                    )
                    return
                if self._is_tainted_or_wraps_tainted(a):
                    # if parser kw passed and is unsafe -> high risk
                    parser_unsafe = False
                    for kw in getattr(node, "keywords", ()):
                        if kw.arg == 'parser':
                            pv = kw.value
                            if isinstance(pv, ast.Call) and self._call_is_parser_constructor(pv) and self._parser_has_unsafe_kwargs(pv):
                                parser_unsafe = True
                                break
                            if isinstance(pv, ast.Name):
                                # resolve assigned parser
                                assigned = self.get_assignment(pv.id)
                                if isinstance(assigned, ast.Call) and self._call_is_parser_constructor(assigned) and self._parser_has_unsafe_kwargs(assigned):
                                    parser_unsafe = True
                                    break
                    if parser_unsafe:
                        self.add_finding(
                            f"XXE_XINCLUDE: Тainted данные передаются в парсер '{pname}' совместно с небезопасным parser=... — риск XInclude/XXE/SSRF",
                            getattr(node, "lineno", 0)
                        )
                        return
                    else:
                        # tainted data alone + later .xinclude() use could be risky; warn conservatively
                        self.add_finding(
                            f"XXE_XINCLUDE: Тainted данные передаются в парсер '{pname}'; проверьте использование XInclude и разрешение внешних ресурсов",
                            getattr(node, "lineno", 0)
                        )
                        return

        # otherwise nothing suspicious
        return
