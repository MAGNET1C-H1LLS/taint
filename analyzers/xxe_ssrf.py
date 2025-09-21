# analyzers/xxe_ssrf.py
import ast
from typing import Optional, Dict
from analyzers.base_analyzer import BaseTaintAnalyzer

class XXESSRFAnalyzer(BaseTaintAnalyzer):
    """
    Heuristic analyzer for XXE -> SSRF:
      - Detects xml parse/fromstring calls receiving tainted input AND
        parser instances/options that allow external entities / network access.
      - Detects XML content literals that contain external SYSTEM/URL declarations.
      - Ignores defusedxml entrypoints.
    Reports findings with type 'XXE_SSRF'.
    """
    def __init__(self, filename: str, tainted_vars: Optional[set] = None, assignments: Optional[Dict[str, ast.AST]] = None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)

        # xml parse entrypoints (similar to XXE file read analyzer)
        self.xml_parse_funcs = {
            'xml.etree.ElementTree.parse',
            'xml.etree.ElementTree.fromstring',
            'xml.etree.ElementTree.XML',
            'xml.etree.fromstring',
            'xml.dom.minidom.parseString',
            'xml.dom.minidom.parse',
            'xml.sax.parse',
            'xml.sax.parseString',
            'lxml.etree.parse',
            'lxml.etree.fromstring',
            'lxml.etree.XML',
            'etree.parse',
            'etree.fromstring',
        }

        # parser constructors that may allow network / entity resolution
        self.parser_constructors = {
            'lxml.etree.XMLParser',
            'xml.sax.make_parser',
            'xml.parsers.expat.ParserCreate',
            'xml.sax.expatreader.ExpatParser',
        }

        # flags/keyword names that hint at entity/network resolution
        self.unsafe_parser_kwargs = {
            'resolve_entities', 'load_dtd', 'no_network', 'external_general_entities',
            'external_parameter_entities', 'huge_tree', 'recover'
        }

        # safe library prefixes (treat as safe)
        self.safe_prefixes = ('defusedxml.',)

    def _is_safe_call(self, func_name: str) -> bool:
        if not func_name:
            return False
        for p in self.safe_prefixes:
            if func_name.startswith(p):
                return True
        return False

    def _call_is_parser_constructor(self, call_node: ast.Call) -> bool:
        fname = self.get_func_name(call_node.func)
        if not fname:
            return False
        if fname in self.parser_constructors:
            return True
        # match short names like XMLParser, make_parser etc.
        base = fname.split('.')[-1]
        for pc in self.parser_constructors:
            if base == pc.split('.')[-1]:
                return True
        return False

    def _parser_has_unsafe_kwargs(self, call_node: ast.Call) -> bool:
        for kw in getattr(call_node, "keywords", ()):
            if not kw.arg:
                continue
            name = kw.arg
            if name in self.unsafe_parser_kwargs:
                # if constant True => unsafe; if non-constant, be conservative => unsafe
                val = kw.value
                if isinstance(val, ast.Constant):
                    try:
                        if bool(val.value) is True:
                            return True
                    except Exception:
                        return True
                else:
                    # conservative
                    return True
        # also check args positionally (some constructors accept booleans)
        for a in call_node.args:
            if isinstance(a, ast.Constant):
                if isinstance(a.value, bool) and a.value is True:
                    # ambiguous: can't be sure which param; be conservative
                    return True
        return False

    def _expr_contains_external_url_literal(self, expr: ast.AST) -> bool:
        """
        Detect explicit XML external SYSTEM/URL constructs or plain http(s) urls in constants.
        e.g. look for substrings: 'SYSTEM "' + 'http://' or '<!ENTITY' with http
        Works only for constants and simple joined strings.
        """
        if expr is None:
            return False

        # Direct constant string
        if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
            s = expr.value.lower()
            if 'system "' in s and ('http://' in s or 'https://' in s):
                return True
            if '<!entity' in s and ('http://' in s or 'https://' in s):
                return True
            # or any literal http url inside xml literal
            if 'http://' in s or 'https://' in s:
                # presence of http url inside an XML literal is suspicious
                return True
            return False

        # f-string / JoinedStr - check formatted parts
        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if isinstance(v, ast.Constant) and isinstance(v.value, str):
                    s = v.value.lower()
                    if 'system "' in s and ('http://' in s or 'https://' in s):
                        return True
                    if '<!entity' in s and ('http://' in s or 'https://' in s):
                        return True
                    if 'http://' in s or 'https://' in s:
                        return True
            return False

        # BinOp concatenation with constants
        if isinstance(expr, ast.BinOp):
            return self._expr_contains_external_url_literal(expr.left) or self._expr_contains_external_url_literal(expr.right)

        # Name / Call / Attribute / Subscript -> try to resolve assignment if present
        if isinstance(expr, ast.Name):
            assigned = self.get_assignment(expr.id)
            if assigned is not None and assigned is not expr:
                return self._expr_contains_external_url_literal(assigned)
            return False

        if isinstance(expr, ast.Call):
            # if call has constant arg containing http url — suspicious
            for a in expr.args:
                if self._expr_contains_external_url_literal(a):
                    return True
            for kw in getattr(expr, "keywords", ()):
                if self._expr_contains_external_url_literal(kw.value):
                    return True
            return False

        # fallback: inspect children
        for child in ast.iter_child_nodes(expr):
            if self._expr_contains_external_url_literal(child):
                return True
        return False

    def _is_tainted_or_wraps_tainted(self, expr: ast.AST) -> bool:
        """Wrapper using BaseTaintAnalyzer.is_tainted + assignment resolution"""
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
            # open(tainted) -> tainted filename
            fname = self.get_func_name(expr.func)
            if fname == 'open' and expr.args:
                return self._is_tainted_or_wraps_tainted(expr.args[0])
            # nested calls -> if any arg tainted -> treat as tainted
            for a in expr.args:
                if self._is_tainted_or_wraps_tainted(a):
                    return True
            for kw in getattr(expr, "keywords", ()):
                if self._is_tainted_or_wraps_tainted(kw.value):
                    return True
            return False

        # check children
        for child in ast.iter_child_nodes(expr):
            if self._is_tainted_or_wraps_tainted(child):
                return True
        return False

    def analyze_vulnerability(self, node: ast.Call):
        """
        Called for each Call AST node.
        Heuristics:
         - if call is XML parse/fromstring AND any data arg is tainted AND (parser kw has unsafe parser OR literal contains external url) -> report XXE_SSRF
         - if parser constructor is created with unsafe kwargs AND there exist tainted data used with parse -> report
         - if constant XML literal contains external URLs -> report (even if not tainted source)
        """
        func_name = self.get_func_name(node.func) or ""

        # ignore explicitly safe libraries
        if self._is_safe_call(func_name):
            return

        # 1) if this call constructs a parser with unsafe flags, warn conservatively if tainted input exists anywhere
        if self._call_is_parser_constructor(node) and self._parser_has_unsafe_kwargs(node):
            # if there are tainted variables in module or any assignment to args that is tainted, warn
            if self.tainted_vars:
                self.add_finding(
                    f"XXE_SSRF: Конструктор парсера '{func_name}' создан с опасными флагами (возможна загрузка внешних сущностей) и в модуле присутствуют ненадёжные данные — возможный SSRF через XXE",
                    getattr(node, "lineno", 0)
                )
                return
            # else still warn as potential if literal external urls occur anywhere (best-effort)
            # We won't search whole module here — leave to parse call analysis below.

        # 2) If call is XML parse/fromstring/... check its args and parser kw
        pure_name = func_name
        is_parse_entry = (pure_name in self.xml_parse_funcs) or any(pure_name.endswith(s.split('.')[-1]) for s in self.xml_parse_funcs)
        if is_parse_entry:
            # check data args for taint or external url literals
            suspicious_data = False
            for a in node.args:
                if self._is_tainted_or_wraps_tainted(a):
                    suspicious_data = True
                    reason = "tainted input"
                    break
                if self._expr_contains_external_url_literal(a):
                    suspicious_data = True
                    reason = "literal external URL/ENTITY in XML"
                    break

            # keywords
            for kw in getattr(node, "keywords", ()):
                if kw.arg == 'parser':
                    # parser passed inline? if parser constructed here with unsafe kwargs -> suspicious
                    pv = kw.value
                    if isinstance(pv, ast.Call):
                        if self._call_is_parser_constructor(pv) and self._parser_has_unsafe_kwargs(pv):
                            # if any data arg is tainted or contains external URL -> report
                            # find data position args (positional above)
                            # we already will check positional args below
                            pass
                    elif isinstance(pv, ast.Name):
                        # parser by name -> we cannot resolve easily; but if there are tainted inputs -> conservative
                        if self.tainted_vars:
                            suspicious_data = True
                            reason = "module contains tainted data and parser passed by name"
                            break
                else:
                    # other keyword may be data
                    if self._is_tainted_or_wraps_tainted(kw.value):
                        suspicious_data = True
                        reason = "tainted input (keyword)"
                        break
                    if self._expr_contains_external_url_literal(kw.value):
                        suspicious_data = True
                        reason = "literal external URL/ENTITY in XML (keyword)"
                        break

            # if data suspicious AND (parser flags unsafe OR literal contains external url) -> report SSRF
            if suspicious_data:
                # examine parser kw or default parser
                parser_unsafe = False
                # parser passed inline as kw
                for kw in getattr(node, "keywords", ()):
                    if kw.arg == 'parser':
                        pv = kw.value
                        if isinstance(pv, ast.Call) and self._call_is_parser_constructor(pv) and self._parser_has_unsafe_kwargs(pv):
                            parser_unsafe = True
                            break
                        if isinstance(pv, ast.Name):
                            # if parser variable assigned earlier to unsafe constructor? attempt assignments map
                            assigned = self.get_assignment(pv.id)
                            if isinstance(assigned, ast.Call) and self._call_is_parser_constructor(assigned) and self._parser_has_unsafe_kwargs(assigned):
                                parser_unsafe = True
                                break
                # if parser_unsafe or literal contained external URL -> SSRF risk
                # We can re-run detection for presence of external URL literal in data args
                data_has_literal_url = any(self._expr_contains_external_url_literal(a) for a in node.args) or any(self._expr_contains_external_url_literal(kw.value) for kw in getattr(node, "keywords", ()))
                if parser_unsafe or data_has_literal_url or reason.startswith("tainted"):
                    self.add_finding(
                        f"XXE_SSRF: Вызов парсера '{func_name}' с {reason} и потенциально небезопасным парсером/внешними ссылками — возможный SSRF через XXE",
                        getattr(node, "lineno", 0)
                    )
                    return

        # 3) If this call uses a parser argument that is a constructor with unsafe kwargs (e.g. parse(..., parser=XMLParser(...)))
        for kw in getattr(node, "keywords", ()):
            if kw.arg == 'parser' and isinstance(kw.value, ast.Call):
                if self._call_is_parser_constructor(kw.value) and self._parser_has_unsafe_kwargs(kw.value):
                    # check positional args for taint or literal urls
                    for a in node.args:
                        if self._is_tainted_or_wraps_tainted(a) or self._expr_contains_external_url_literal(a):
                            self.add_finding(
                                f"XXE_SSRF: Парсер (parser=...) с небезопасными флагами {self.get_func_name(kw.value.func)} используется вместе с ненадёжными данными — возможный SSRF",
                                getattr(node, "lineno", 0)
                            )
                            return
        # default: nothing suspicious
        return
