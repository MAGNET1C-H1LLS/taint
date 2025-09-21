# analyzers/xxe_file_read.py
import ast
from typing import Optional, Dict
from analyzers.base_analyzer import BaseTaintAnalyzer

class XXEFileReadAnalyzer(BaseTaintAnalyzer):
    """
    Detect XXE-like patterns that may lead to reading internal files:
      - xml parsing functions receiving untrusted input (parse/fromstring/etc.)
      - use of unsafe XMLParser constructions (lxml.etree.XMLParser(load_dtd=True, resolve_entities=True))
      - parsing file paths / file-like objects coming from untrusted sources
    Heuristics-based; reports potential XXE_FILE_READ findings.
    """
    def __init__(self, filename: str, tainted_vars: Optional[set] = None, assignments: Optional[Dict[str, ast.AST]] = None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)

        # common XML parse entrypoints that can process external entities or file paths
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
            'etree.parse',  # sometimes used when imported as "from lxml import etree"
            'etree.fromstring',
        }

        # constructors that can create potentially unsafe parsers (lxml, xml.sax)
        self.parser_constructors = {
            'lxml.etree.XMLParser',
            'xml.sax.make_parser',
            'xml.sax.expatreader.ExpatParser',
            'xml.parsers.expat.ParserCreate',
        }

        # safe library indicators (treat defusedxml functions as safe)
        self.safe_prefixes = ('defusedxml.',)

        # keywords in XMLParser constructor which, if True, increase risk
        self.unsafe_parser_kwargs = {'resolve_entities', 'load_dtd', 'no_network', 'external_general_entities', 'external_parameter_entities'}

    def _is_safe_call(self, func_name: str) -> bool:
        if not func_name:
            return False
        for p in self.safe_prefixes:
            if func_name.startswith(p):
                return True
        return False

    def _call_is_xml_parser_constructor(self, node: ast.Call) -> bool:
        """Return True if call_node is a constructor of a parser we consider (by name)."""
        fname = self.get_func_name(node.func)
        if not fname:
            return False
        # direct match or short names
        if fname in self.parser_constructors:
            return True
        # sometimes user imported lxml.etree as etree
        if any(fname.endswith(p.split('.')[-1]) for p in self.parser_constructors):
            # e.g., 'XMLParser' or 'make_parser' - check presence
            return fname.split('.')[-1] in {p.split('.')[-1] for p in self.parser_constructors}
        return False

    def _parser_has_unsafe_kwargs(self, node: ast.Call) -> bool:
        """Check keywords for flags that indicate entity resolution / DTD / network access enabled."""
        for kw in getattr(node, "keywords", ()):
            k = kw.arg
            if not k:
                continue
            if k in self.unsafe_parser_kwargs:
                # if kw value is a Constant True -> unsafe, if it's Name check assignments/constness is complicated
                if isinstance(kw.value, ast.Constant):
                    if bool(kw.value.value) is True:
                        return True
                else:
                    # conservative: consider non-constant true-like as potentially unsafe
                    return True
        return False

    def _expr_is_tainted_or_wraps_tainted(self, expr: ast.AST) -> bool:
        """Wrapper to decide if an expression is tainted (directly or via assignments)."""
        # direct quick check
        try:
            if self.is_tainted(expr):
                return True
        except Exception:
            pass

        # If expression is a Name -> check last assignment
        if isinstance(expr, ast.Name):
            assigned = self.get_assignment(expr.id)
            if assigned is not None and assigned is not expr:
                return self._expr_is_tainted_or_wraps_tainted(assigned)
            return False

        # Call: e.g. open(tainted) or somefunc(tainted)
        if isinstance(expr, ast.Call):
            # open(tainted) -> tainted filename passed to parse
            fname = self.get_func_name(expr.func)
            if fname == 'open':
                # check first arg
                if expr.args:
                    return self._expr_is_tainted_or_wraps_tainted(expr.args[0])
                return False
            # nested calls: if any arg is tainted -> treat call result as tainted
            for a in expr.args:
                if self._expr_is_tainted_or_wraps_tainted(a):
                    return True
            for kw in getattr(expr, "keywords", ()):
                if self._expr_is_tainted_or_wraps_tainted(kw.value):
                    return True
            return False

        # Attribute/Subscript etc -> check children
        for child in ast.iter_child_nodes(expr):
            if self._expr_is_tainted_or_wraps_tainted(child):
                return True
        return False

    def analyze_vulnerability(self, node: ast.Call):
        """
        Called for each Call node:
         - if call is xml parse/fromstring/... and its first arg is tainted -> report XXE_FILE_READ
         - if call uses a parser object created with unsafe kwargs and input is tainted -> report
         - do not report if call belongs to safe lib (defusedxml)
        """
        func_name = self.get_func_name(node.func) or ""

        # skip if explicitly safe lib
        if self._is_safe_call(func_name):
            return

        # 1) If this call is an XML parse entrypoint
        pure_name = func_name
        if pure_name in self.xml_parse_funcs or any(pure_name.endswith(s.split('.')[-1]) for s in self.xml_parse_funcs):
            # check args: many parse/fromstring functions accept either a string (xml content) or filename/file object
            # We'll conservatively check all args and keywords for taint
            # check positional args
            for a in node.args:
                if self._expr_is_tainted_or_wraps_tainted(a):
                    self.add_finding(
                        f"XXE_FILE_READ: Парсер XML '{func_name}' получает данные из ненадёжного источника — возможное чтение внутренних файлов/внешних сущностей",
                        getattr(node, "lineno", 0)
                    )
                    return
            # check keyword args
            for kw in getattr(node, "keywords", ()):
                if self._expr_is_tainted_or_wraps_tainted(kw.value):
                    self.add_finding(
                        f"XXE_FILE_READ: Парсер XML '{func_name}' получает данные из ненадёжного источника (keyword {kw.arg}) — возможное чтение внутренних файлов/внешних сущностей",
                        getattr(node, "lineno", 0)
                    )
                    return

        # 2) If this call constructs a parser with unsafe kwargs (e.g. lxml.etree.XMLParser(load_dtd=True,...))
        if self._call_is_xml_parser_constructor(node):
            if self._parser_has_unsafe_kwargs(node):
                # If this parser instance is later passed to a parse(...) call with user data / file => vulnerability.
                # We try to detect immediate use: parent of this call might be assigned to a var, or used inline in parse(parser=...)
                parent = getattr(node, "parent", None)
                assigned_name = None
                if isinstance(parent, ast.Assign):
                    # e.g., p = XMLParser(load_dtd=True)
                    for tgt in parent.targets:
                        if isinstance(tgt, ast.Name):
                            assigned_name = tgt.id
                # search for usages of this assigned_name in same module (simple heuristic)
                if assigned_name:
                    # look through assignments map for RHS calls that pass this parser as keyword/arg into parse calls
                    for name, rhs in self.assignments.items():
                        # rhs is last assigned expression for 'name' — not exactly usages. Instead, walk AST? We'll do local scan:
                        pass  # we keep conservative approach: treat creation of unsafe parser as potential risk if any tainted data exists globally
                    # conservative check: if there is any tainted var in module, report potential
                    if self.tainted_vars:
                        self.add_finding(
                            f"XXE_FILE_READ: Создан потенциально небезопасный XML parser '{self.get_func_name(node.func)}' с опасными флагами и присутствуют ненадёжные данные в модуле — возможное XXE через парсер '{assigned_name}'",
                            getattr(node, "lineno", 0)
                        )
                        return
                else:
                    # parser created inline (unlikely) — still warn if any tainted arg later used in parse (best-effort)
                    if self.tainted_vars:
                        self.add_finding(
                            f"XXE_FILE_READ: Создан потенциально небезопасный XML parser '{self.get_func_name(node.func)}' с опасными флагами — проверьте использование с ненадёжными данными",
                            getattr(node, "lineno", 0)
                        )
                        return

        # 3) If parse is called with a parser argument (e.g., etree.parse(src, parser=XMLParser(...)))
        #   then node.func may be parse; if so, check parser kw and src arg taint
        # We already handled parse entrypoints for tainted args above; additionally check keyword 'parser' if present:
        for kw in getattr(node, "keywords", ()):
            if kw.arg == 'parser':
                # kw.value may be a Call constructing XMLParser(...) or a Name referencing previously constructed parser
                pv = kw.value
                if isinstance(pv, ast.Call) and self._call_is_xml_parser_constructor(pv) and self._parser_has_unsafe_kwargs(pv):
                    # if any data arg is tainted -> report
                    for a in node.args:
                        if self._expr_is_tainted_or_wraps_tainted(a):
                            self.add_finding(
                                f"XXE_FILE_READ: Парсер с небезопасными флагами передан в вызов '{func_name}', а источник данных таinted — возможное чтение внутренних файлов",
                                getattr(node, "lineno", 0)
                            )
                            return
                    # also check keywords for data
                    for k2 in getattr(node, "keywords", ()):
                        if k2.arg in (None, 'source', 'filename', 'string') and self._expr_is_tainted_or_wraps_tainted(k2.value):
                            self.add_finding(
                                f"XXE_FILE_READ: Парсер с небезопасными флагами передан в вызов '{func_name}', а keyword-аргумент источника таinted — возможное чтение внутренних файлов",
                                getattr(node, "lineno", 0)
                            )
                            return
                # if parser passed by name (Name) - we cannot reliably resolve here; be conservative if any tainted var exists
                if isinstance(pv, ast.Name):
                    if self.tainted_vars:
                        self.add_finding(
                            f"XXE_FILE_READ: Вызов '{func_name}' использует parser '{pv.id}', который может быть небезопасным — присутствуют ненадёжные данные в модуле",
                            getattr(node, "lineno", 0)
                        )
                        return

        # else: nothing suspicious detected for this node
        return
