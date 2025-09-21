# analyzers/custom_sanitizer.py
import ast
from typing import Dict, Optional
from analyzers.base_analyzer import BaseTaintAnalyzer

class CustomSanitizerAnalyzer(BaseTaintAnalyzer):
    """
    Анализатор пользовательских санитайзеров (wrappers).
    - Сканирует определения функций (FunctionDef) и пытается классифицировать
      функции-обёртки над санитайзерами как:
         'sufficient'  - возвращает значение ровно из вызова безопасного санитайзера
         'ineffective' - использует очевидно слабые операции (replace/strip/lower/upper) или небезопасные трансформации
         'unknown'     - нельзя однозначно решить
    - Далее при обнаружении передачи результата такого санитайзера в sink
      добавляет finding если санитайзер 'ineffective' или 'unknown' (консервативно).
    """
    def __init__(self, filename: str, tainted_vars: Optional[set] = None, assignments: Optional[Dict[str, ast.AST]] = None):
        super().__init__(filename, tainted_vars=tainted_vars, assignments=assignments)
        # name -> ast.FunctionDef
        self.func_defs: Dict[str, ast.FunctionDef] = {}
        # name -> classification: 'sufficient'|'ineffective'|'unknown'
        self.user_sanitizers: Dict[str, str] = {}

        # Можно расширить список "сильных" санитайзеров — используем базовый self.sanitizers из BaseTaintAnalyzer
        # and self.ineffective_sanitizers also from base
        # self.sanitizers и self.ineffective_sanitizers уже доступны

        # Sink-ish names we consider relevant for sanitizer evaluation (heuristic)
        self.sink_keywords = ("execute", "executemany", "query", "cursor.execute",
                              "redirect", "location", "render", "template", "href",
                              "log", "logging.", "logger.", "write", "send")

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Collect function defs to analyze their return expressions later
        try:
            self.func_defs[node.name] = node
        except Exception:
            pass

        # Try to classify immediately if possible (fast path)
        classification = self._classify_wrapper_function(node)
        if classification is not None:
            self.user_sanitizers[node.name] = classification
        else:
            # leave as 'unknown' for now; we may re-classify later if needed
            self.user_sanitizers.setdefault(node.name, "unknown")

        # continue traversal to collect nested defs too
        self.generic_visit(node)

    def _classify_wrapper_function(self, node: ast.FunctionDef) -> Optional[str]:
        """
        Analyze the function body to determine if it is a wrapper over known sanitizer.
        Heuristics:
         - If all return statements are exactly a Call to a known sanitizer with a parameter -> 'sufficient'
         - If any return uses ineffective sanitizers (strip/replace/lower/upper) -> 'ineffective'
         - If return builds strings by concatenation / f-strings with parameter -> 'ineffective'
         - If returns parameter unchanged -> 'noop' (treated as 'ineffective' here)
         - Otherwise -> None (unknown)
        """
        returns = []
        for n in ast.walk(node):
            if isinstance(n, ast.Return):
                if n.value is not None:
                    returns.append(n.value)
                else:
                    returns.append(None)

        if not returns:
            return None

        all_sufficient = True
        any_ineffective = False
        any_noop = False

        # get list of param names
        params = [p.arg for p in node.args.args]

        for ret in returns:
            if ret is None:
                # return without value -> treat as unknown
                return None

            # If return is a direct call to known sanitizer, and its argument is exactly one of params -> sufficient
            if isinstance(ret, ast.Call):
                fname = self.get_func_name(ret.func)
                # if the call is to known built-in sanitizer
                if fname in self.sanitizers:
                    # ensure arg is parameter (Name) or expression derived directly from param
                    if len(ret.args) >= 1 and isinstance(ret.args[0], ast.Name) and ret.args[0].id in params:
                        # ok
                        continue
                    else:
                        # returns sanitizer(some complex expr) — still could be ok but treat unknown
                        all_sufficient = False
                        continue
                # if call chain includes known sanitizer (e.g. html.escape(param).strip())
                # check nested call nodes inside ret for sanitizer
                found_strong = False
                for c in ast.walk(ret):
                    if isinstance(c, ast.Call):
                        cf = self.get_func_name(c.func)
                        if cf in self.sanitizers:
                            found_strong = True
                            break
                if found_strong:
                    # but if after sanitizer there's concat/format -> might be unsafe; we'll be conservative:
                    # if ret is exactly a call (not part of BinOp or JoinedStr), consider sufficient
                    if isinstance(ret.func, (ast.Name, ast.Attribute)):
                        # ret is a call expression that contains sanitizer deeper -> assume sufficient
                        continue
                    else:
                        all_sufficient = False
                        continue

                # if call is to ineffective sanitizer (like replace/strip/..)
                if fname in self.ineffective_sanitizers:
                    any_ineffective = True
                    all_sufficient = False
                    continue

                # otherwise unknown call
                all_sufficient = False
                continue

            # return is just Name(param) -> noop -> ineffective
            if isinstance(ret, ast.Name) and ret.id in params:
                any_noop = True
                all_sufficient = False
                continue

            # return is BinOp (concatenation or % formatting) involving param -> ineffective
            if isinstance(ret, ast.BinOp):
                # if any Name node inside is a param -> likely unsafe
                for n in ast.walk(ret):
                    if isinstance(n, ast.Name) and n.id in params:
                        any_ineffective = True
                        all_sufficient = False
                        break
                continue

            # f-string / JoinedStr involving param -> ineffective
            if isinstance(ret, ast.JoinedStr):
                for n in ast.walk(ret):
                    if isinstance(n, ast.FormattedValue):
                        if isinstance(n.value, ast.Name) and n.value.id in params:
                            any_ineffective = True
                            all_sufficient = False
                            break
                continue

            # otherwise be conservative -> unknown
            return None

        # decide classification
        if all_sufficient:
            return "sufficient"
        if any_ineffective or any_noop:
            return "ineffective"
        return "unknown"

    def analyze_vulnerability(self, node: ast.Call):
        """
        При проходе по вызовам — если в аргументе находится вызов пользовательского санитайзера
        или переменная, в которой хранится результат такого санитайзера — реагируем:
         - sufficient -> считаем безопасным, пропускаем
         - ineffective/unknown -> добавляем finding типа 'SANITIZERCHAIN' с пояснением
        """
        func_name = self.get_func_name(node.func) or "<unknown>"

        # helper: if arg is a call to user sanitizer -> classification
        def classify_call_arg(call_node: ast.Call) -> Optional[str]:
            # name of function called
            fname = self.get_func_name(call_node.func)
            if not fname:
                return None
            # if function is a user-defined wrapper we classified earlier
            if fname in self.user_sanitizers:
                return self.user_sanitizers[fname]
            # if the function called is itself a built-in sanitizer -> sufficient
            if fname in self.sanitizers:
                return "sufficient"
            # otherwise unknown
            return None

        # 1) inspect positional args
        for arg in node.args:
            # case: inline call e.g. cursor.execute(sanitize(x))
            if isinstance(arg, ast.Call):
                cls = classify_call_arg(arg)
                if cls is None:
                    # If call wraps built-in sanitizer deeper, try to detect
                    # we already attempted in classification; if not found -> skip
                    pass
                elif cls == "sufficient":
                    # OK — skip
                    pass
                else:
                    # ineffective or unknown -> if inner arg uses taint -> report
                    # check if call's args are tainted
                    for a in arg.args:
                        if self.is_tainted(a):
                            self.add_finding(
                                f"Sanitizer Chain: пользовательский санитайзер '{self.get_func_name(arg.func)}' помечен как '{cls}' — tainted данные проходят через него в {func_name}",
                                getattr(node, "lineno", 0)
                            )
                            # one finding per arg is enough
                            break

            # case: variable which may have been assigned from sanitizer earlier
            if isinstance(arg, ast.Name):
                assigned = self.get_assignment(arg.id)
                if assigned is None:
                    continue
                if isinstance(assigned, ast.Call):
                    cls = classify_call_arg(assigned)
                    if cls is None:
                        continue
                    if cls == "sufficient":
                        continue
                    # if assigned RHS call returns tainted (via interproc/prepass), or argument was tainted originally
                    # check if the original argument to the sanitizer contains taint
                    for a in assigned.args:
                        if self.is_tainted(a):
                            self.add_finding(
                                f"Sanitizer Chain: переменная '{arg.id}' содержит результат пользовательского санитайзера '{self.get_func_name(assigned.func)}' помеченного как '{cls}', и затем используется в {func_name}",
                                getattr(node, "lineno", 0)
                            )
                            break

        # 2) keywords
        for kw in getattr(node, "keywords", ()):
            val = kw.value
            if isinstance(val, ast.Call):
                cls = classify_call_arg(val)
                if cls and cls != "sufficient":
                    for a in val.args:
                        if self.is_tainted(a):
                            self.add_finding(
                                f"Sanitizer Chain: пользовательский санитайзер '{self.get_func_name(val.func)}' помечен как '{cls}' — tainted данные через него попадают в {func_name} (keyword {kw.arg})",
                                getattr(node, "lineno", 0)
                            )
                            break
            if isinstance(val, ast.Name):
                assigned = self.get_assignment(val.id)
                if isinstance(assigned, ast.Call):
                    cls = classify_call_arg(assigned)
                    if cls and cls != "sufficient":
                        for a in assigned.args:
                            if self.is_tainted(a):
                                self.add_finding(
                                    f"Sanitizer Chain: переменная '{val.id}' содержит результат пользовательского санитайзера '{self.get_func_name(assigned.func)}' помеченного как '{cls}', и затем используется в {func_name} (keyword {kw.arg})",
                                    getattr(node, "lineno", 0)
                                )
                                break

        # no generic return — continue traversal via BaseTaintAnalyzer
