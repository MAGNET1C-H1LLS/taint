# main.py
import ast
import argparse
from utils.analyzer_loader import load_analyzers
from utils.ast_helpers import add_parent_links
from utils.taint_prepass import TaintPrepass

def parse_args():
    parser = argparse.ArgumentParser(description="Dynamic Taint Analysis for Python code")
    parser.add_argument(
        "-t",
        "--taint",
        metavar="FILE",
        required=True,
        help="Perform taint analysis of the given file",
    )
    parser.add_argument(
        "--analyzers-dir",
        default="analyzers",
        help="Directory/package containing analyzer modules"
    )
    parser.add_argument(
        "--only",
        nargs="*",
        help="(optional) list of analyzer class names to run (по умолчанию — все найденные)"
    )
    return parser.parse_args()

def run_analysis(filename, analyzers_dir, only_list=None):
    analyzers_classes = load_analyzers(analyzers_dir)

    if not analyzers_classes:
        print("Не найдено ни одного анализатора!")
        return []

    if only_list:
        analyzers_classes = [c for c in analyzers_classes if c.__name__ in only_list]
        if not analyzers_classes:
            print("После фильтрации по --only анализаторов не осталось.")
            return []

    print(f"Загружено анализаторов: {len(analyzers_classes)}")
    for cls in analyzers_classes:
        print(f"  - {cls.__name__}")

    with open(filename, "r", encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=filename)
    add_parent_links(tree)

    # pre-pass: построим assignments и tainted_vars в фиксированной точке
    pre = TaintPrepass()
    assignments, tainted_vars = pre.run(tree)
    print(f"[prepass] выявлено tainted_vars: {sorted(list(tainted_vars))}")

    analyzers = []
    for cls in analyzers_classes:
        try:
            # передаём результаты pre-pass в конструктор анализатора
            analyzers.append(cls(filename, tainted_vars=tainted_vars, assignments=assignments))
        except Exception as e:
            print(f"Ошибка инициализации анализатора {cls.__name__}: {e}")

    all_findings = []
    for analyzer in analyzers:
        analyzer.visit(tree)
        all_findings.extend(analyzer.findings)

    return all_findings

def main():
    args = parse_args()
    input_file = args.taint
    findings = run_analysis(input_file, args.analyzers_dir, args.only)

    header = f"Результаты анализа файла {input_file}:\n" + "=" * 60
    print(header)

    if not findings:
        print("Уязвимостей не обнаружено")
        return

    findings_by_type = {}
    for f in findings:
        t = f.get('type', 'Unknown')
        findings_by_type.setdefault(t, []).append(f)

    for vuln_type, entries in findings_by_type.items():
        section = f"\n=== {vuln_type.upper()} ({len(entries)} найден(о)) ==="
        print(section)
        for e in entries:
            print(f"Строка {e.get('line', '?')}: {e.get('message', '')}")

if __name__ == "__main__":
    main()
