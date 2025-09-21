# analyzers/interprocedural_recursive.py
import ast
from typing import Dict, Tuple, Optional, List
from analyzers.base_analyzer import BaseTaintAnalyzer
import sys

def _debug(*args):
    print("[interproc.debug]", *args, file=sys.stderr)

class InterproceduralAnalyzer(BaseTaintAnalyzer):
    """
    Улучшенный межпроцедурный анализатор с подстановкой параметров (param -> AST).
    Поддерживает:
      - подстановку реального AST-выражения параметра при анализе return'ов функции,
        что позволяет распознавать случаи типа: def f(req): return req.args['id']; f(request)
      - кеширование и ограничение глубины
    Ограничения:
      - только локальные FunctionDef в том же модуле
      - простая поддержка lambda/kwargs/varargs
    """
    def __init__(self, filename: str, tainted_vars: Optional[set] = None, assignments: Optional[Dict[str, ast.AST]] = None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        self.func_defs: Dict[str, ast.FunctionDef] = {}
        self._call_cache: Dict[Tuple[str, Tuple[bool, ...]], bool] = {}
        self.max_depth: int = 6

    def visit_FunctionDef(self, node: ast.FunctionDef):
        try:
            self.func_defs[node.name] = node
            _debug("collected func", node.name, "lineno", getattr(node, "lineno", "?"))
        except Exception:
            pass
        self.generic_visit(node)

    def _map_args_to_params(self, call_node: ast.Call, func_def: ast.FunctionDef) -> Dict[str, Optional[ast.AST]]:
        mapping: Dict[str, Optional[ast.AST]] = {}
        params = [p.arg for p in func_def.args.args]
        for i, pname in enumerate(params):
            if i < len(call_node.args):
                mapping[pname] = call_node.args[i]
            else:
                mapping[pname] = None
        for kw in getattr(call_node, "keywords", ()):
            if kw.arg is not None:
                mapping[kw.arg] = kw.value
        return mapping

    def _expr_tainted_with_locals(self,
                                  expr: Optional[ast.AST],
                                  local_taint: Dict[str, bool],
                                  local_expr_map: Dict[str, Optional[ast.AST]],
                                  depth: int) -> bool:
        """
        Проверяет, tainted ли expr с учётом:
          - local_taint: param_name -> bool (tainted)
          - local_expr_map: param_name -> AST (реальное выражение, переданное в параметр)
        Подстановка local_expr_map решает кейсы типа req.args -> request.args
        """
        if expr is None:
            return False
        if depth > self.max_depth:
            _debug("depth exceeded in _expr", depth)
            return False

        # Name: если это параметр — подставим реальное выражение, если есть
        if isinstance(expr, ast.Name):
            name = expr.id
            if local_taint.get(name, False):
                _debug("local param tainted:", name)
                return True
            # если есть реальное переданное выражение для параметра, проверим его
            if name in local_expr_map and local_expr_map[name] is not None:
                mapped = local_expr_map[name]
                # предотвратить бесконечность: если mapped == expr, пропускаем
                if mapped is not expr:
                    _debug("substituting param", name, "->", ast.dump(mapped)[:120])
                    return self._expr_tainted_with_locals(mapped, local_taint, local_expr_map, depth + 1)
            # глобальные tainted переменные
            if name in self.tainted_vars:
                _debug("global tainted name:", name)
                return True
            assigned = self.get_assignment(name)
            if assigned is not None and assigned is not expr:
                return self._expr_tainted_with_locals(assigned, local_taint, local_expr_map, depth + 1)
            return False

        # Lambda: check body for no-arg lambdas
        if isinstance(expr, ast.Lambda):
            if getattr(expr.args, "args", None):
                if len(expr.args.args) == 0:
                    return self._expr_tainted_with_locals(expr.body, local_taint, local_expr_map, depth + 1)
                return False

        # Call: source? args? nested calls? local function returns?
        if isinstance(expr, ast.Call):
            try:
                if self.is_source_call(expr):
                    _debug("call is source:", self.get_func_name(expr.func))
                    return True
            except Exception:
                pass

            for a in expr.args:
                if self._expr_tainted_with_locals(a, local_taint, local_expr_map, depth + 1):
                    return True
            for kw in getattr(expr, "keywords", ()):
                if self._expr_tainted_with_locals(kw.value, local_taint, local_expr_map, depth + 1):
                    return True

            return self._call_returns_tainted(expr, depth + 1)

        # Attribute: try to substitute parameter if attribute.value is a parameter name
        if isinstance(expr, ast.Attribute):
            # if value is Name and maps to a passed AST -> create substituted attribute and re-evaluate
            if isinstance(expr.value, ast.Name):
                pname = expr.value.id
                if pname in local_expr_map and local_expr_map[pname] is not None:
                    substituted = ast.Attribute(value=local_expr_map[pname], attr=expr.attr, ctx=expr.ctx)
                    _debug("attribute substitution:", pname, "->", ast.dump(local_expr_map[pname])[:120], "attr", expr.attr)
                    return self._expr_tainted_with_locals(substituted, local_taint, local_expr_map, depth + 1)
            # otherwise check full name against sources (e.g., request.args)
            full = self.get_func_name(expr)
            if full and full in self.sources:
                _debug("attribute is source:", full)
                return True
            return self._expr_tainted_with_locals(expr.value, local_taint, local_expr_map, depth + 1)

        # Subscript: substitute like Attribute
        if isinstance(expr, ast.Subscript):
            # if value is Name param and maps -> substitute
            if isinstance(expr.value, ast.Name):
                pname = expr.value.id
                if pname in local_expr_map and local_expr_map[pname] is not None:
                    substituted_value = local_expr_map[pname]
                    # build new Subscript(value=substituted_value, slice=expr.slice)
                    substituted = ast.Subscript(value=substituted_value, slice=expr.slice, ctx=expr.ctx)
                    return self._expr_tainted_with_locals(substituted, local_taint, local_expr_map, depth + 1)
            # else check components
            if self._expr_tainted_with_locals(expr.value, local_taint, local_expr_map, depth + 1):
                return True
            if hasattr(expr, "slice") and expr.slice is not None:
                return self._expr_tainted_with_locals(expr.slice, local_taint, local_expr_map, depth + 1)
            return False

        if isinstance(expr, ast.BinOp):
            return (self._expr_tainted_with_locals(expr.left, local_taint, local_expr_map, depth + 1) or
                    self._expr_tainted_with_locals(expr.right, local_taint, local_expr_map, depth + 1))

        if isinstance(expr, ast.JoinedStr):
            for v in expr.values:
                if self._expr_tainted_with_locals(v, local_taint, local_expr_map, depth + 1):
                    return True
            return False

        if isinstance(expr, ast.FormattedValue):
            return self._expr_tainted_with_locals(expr.value, local_taint, local_expr_map, depth + 1)

        if isinstance(expr, (ast.Constant,)):
            return False

        for child in ast.iter_child_nodes(expr):
            if self._expr_tainted_with_locals(child, local_taint, local_expr_map, depth + 1):
                return True
        return False

    def _call_signature(self, call_node: ast.Call) -> Tuple[bool, ...]:
        sig: List[bool] = []
        for a in call_node.args:
            if isinstance(a, ast.Call):
                try:
                    nested = self._call_returns_tainted(a, depth=0)
                except Exception:
                    nested = False
                sig.append(bool(nested or self.is_tainted(a)))
            else:
                sig.append(bool(self.is_tainted(a)))
        return tuple(sig)

    def _call_returns_tainted(self, call_node: ast.Call, depth: int = 0) -> bool:
        if call_node is None:
            return False
        if depth > self.max_depth:
            _debug("depth exceeded in _call", depth, "func", self.get_func_name(call_node.func))
            return False

        func_name = self.get_func_name(call_node.func) or ""
        arg_sig = self._call_signature(call_node)
        cache_key = (func_name, arg_sig)
        if cache_key in self._call_cache:
            _debug("cache hit", cache_key, "->", self._call_cache[cache_key])
            return self._call_cache[cache_key]

        # 1) direct args taint or nested calls
        for a in call_node.args:
            if isinstance(a, ast.Call):
                if self._call_returns_tainted(a, depth + 1):
                    self._call_cache[cache_key] = True
                    _debug("nested arg call returns tainted for", func_name)
                    return True
            else:
                if self.is_tainted(a):
                    self._call_cache[cache_key] = True
                    _debug("direct tainted arg for", func_name, "arg", ast.dump(a)[:120])
                    return True
        for kw in getattr(call_node, "keywords", ()):
            if isinstance(kw.value, ast.Call):
                if self._call_returns_tainted(kw.value, depth + 1):
                    self._call_cache[cache_key] = True
                    return True
            else:
                if self.is_tainted(kw.value):
                    self._call_cache[cache_key] = True
                    return True

        # 2) local function: simulate returns with param substitution map
        func_def = self.func_defs.get(func_name)
        if func_def:
            arg_map = self._map_args_to_params(call_node, func_def)
            # prepare both taint flags and actual param->AST map
            local_taint: Dict[str, bool] = {}
            local_expr_map: Dict[str, Optional[ast.AST]] = {}
            for pname, pval in arg_map.items():
                local_expr_map[pname] = pval
                if pval is None:
                    local_taint[pname] = False
                else:
                    if isinstance(pval, ast.Call):
                        local_taint[pname] = self._call_returns_tainted(pval, depth + 1)
                    else:
                        local_taint[pname] = self.is_tainted(pval)

            returns_tainted = False
            for n in ast.walk(func_def):
                if isinstance(n, ast.Return) and n.value is not None:
                    try:
                        if self._expr_tainted_with_locals(n.value, local_taint, local_expr_map, depth + 1):
                            returns_tainted = True
                            _debug("function", func_name, "returns tainted via return at lineno", getattr(n, "lineno", "?"))
                            break
                    except Exception:
                        pass

            self._call_cache[cache_key] = returns_tainted
            return returns_tainted

        self._call_cache[cache_key] = False
        return False

    def _classify_sink(self, func_name: str) -> str:
        low = (func_name or "").lower()
        if any(p in low for p in ("execute", "executemany", "query", "cursor.execute", "cursor.executemany")):
            return "SQLINJECTION"
        if "redirect" in low or "location" in low or low.endswith("redirect"):
            return "OPENREDIRECT"
        if any(p in low for p in ("render", "template", "href", "innerhtml", "write")):
            return "XSS"
        if low.startswith("log") or ".log" in low or any(p in low for p in ("logger.", "logging.")):
            return "LOGINJECTION"
        return "INTERPROCEDURAL"

    def analyze_vulnerability(self, node: ast.Call):
        try:
            func_name = self.get_func_name(node.func) or "<unknown>"
        except Exception:
            func_name = "<unknown>"

        # nested-call-as-argument -> report
        for arg in node.args:
            if isinstance(arg, ast.Call):
                try:
                    if self._call_returns_tainted(arg, depth=0):
                        sink_type = self._classify_sink(func_name)
                        msg = f"{sink_type}: tainted данные проходят через вызов {self.get_func_name(arg.func)} и передаются в {func_name}"
                        _debug("reporting", sink_type, "for call", func_name, "arg func", self.get_func_name(arg.func))
                        self.findings.append({
                            "type": sink_type,
                            "message": msg,
                            "line": getattr(node, "lineno", 0),
                            "file": self.filename
                        })
                        parent = getattr(node, "parent", None)
                        if isinstance(parent, ast.Assign):
                            for tgt in parent.targets:
                                if isinstance(tgt, ast.Name):
                                    self.tainted_vars.add(tgt.id)
                except Exception as e:
                    _debug("error while checking nested arg", e)

        # if whole call returns tainted and assigned -> mark LHS
        try:
            if self._call_returns_tainted(node, depth=0):
                parent = getattr(node, "parent", None)
                if isinstance(parent, ast.Assign):
                    for tgt in parent.targets:
                        if isinstance(tgt, ast.Name):
                            if tgt.id not in self.tainted_vars:
                                self.tainted_vars.add(tgt.id)
                                self.findings.append({
                                    "type": "INTERPROCEDURAL",
                                    "message": f"Interprocedural: переменная '{tgt.id}' помечена как tainted (результат вызова {func_name})",
                                    "line": getattr(node, "lineno", 0),
                                    "file": self.filename
                                })
                                _debug("marked var tainted", tgt.id, "from call", func_name)
        except Exception as e:
            _debug("error while checking call itself", e)
