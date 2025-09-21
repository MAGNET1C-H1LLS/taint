import ast
import argparse
import json
import matplotlib.pyplot as plt
from matplotlib.text import Text

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
)


# ---------------- AST Analyzer ---------------- #
class ASTAnalyzer(ast.NodeVisitor):
    def __init__(self, filename):
        self.issues = []
        self.filename = filename

    def report(self, rule_id, message, node):
        self.issues.append(
            {
                "ruleId": rule_id,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": self.filename},
                            "region": {
                                "startLine": node.lineno,
                                "startColumn": node.col_offset,
                            },
                        }
                    }
                ],
            }
        )

    def visit_If(self, node):
        if isinstance(node.test, ast.Constant) and isinstance(node.test.value, bool):
            self.report("USELESS_IF", "Condition is always true/false", node)
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name):
            if node.func.id == "eval":
                self.report("USE_OF_EVAL", "Potential code injection vulnerability", node)
            elif node.func.id == "exec":
                self.report(
                    "USE_OF_EXEC",
                    "Use of exec() detected, which can lead to code injection vulnerabilities",
                    node,
                )
        self.generic_visit(node)

    def visit_Compare(self, node):
        if isinstance(node.ops[0], ast.Is):
            left = node.left
            right = node.comparators[0]
            if isinstance(left, ast.Constant) or isinstance(right, ast.Constant):
                self.report("LITERAL_IS", "Comparison using 'is' with literal values", node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if node.returns is None:
            self.report("MISSING_RETURN_TYPE", "Missing function return type annotation", node)
        self.generic_visit(node)


# ---------------- CLI ---------------- #
def parse_args():
    parser = argparse.ArgumentParser(
        description="AST utility: parse (-p), visualize (-v), analyze (-a)"
    )
    parser.add_argument(
        "-p", "--parse", nargs="+", metavar="FILE", help="Dump AST for Python files"
    )
    parser.add_argument(
        "-v",
        "--visualize",
        nargs=2,
        metavar=("FILE", "OUT"),
        help="Visualize AST as structured tree image",
    )
    parser.add_argument(
        "-a",
        "--analyze",
        nargs=2,
        metavar=("FILE", "OUT"),
        help="Analyze file and output SARIF JSON",
    )
    return parser.parse_args()


# ---------------- AST Dump ---------------- #
def dump_ast(fpath):
    with open(fpath, "r", encoding="utf-8") as f:
        src = f.read()
    tree = ast.parse(src, filename=fpath)
    print(ast.dump(tree, include_attributes=True, indent=2))


# ---------------- AST Visualization ---------------- #
def visualize_ast(fpath, outpath):
    """
    Парсит Python-файл и строит визуализацию его AST в виде графа узлов и рёбер.

    fpath: путь к .py файлу с исходным кодом
    outpath: путь к выходному изображению (например, .png)
    """
    # 1. Чтение исходных данных
    # -------------------------
    # Открываем файл в кодировке UTF-8 и читаем весь код в строку src.
    with open(fpath, 'r', encoding='utf-8') as f:
        src = f.read()

    # 2. Преобразование кода в AST
    # -----------------------------
    # ast.parse строит дерево разбора на основе текста src.
    # Параметр filename добавляет контекст в случае ошибок.
    tree = ast.parse(src, filename=fpath)

    # 3. Создание "псевдо-фигуры" для измерения текста
    # --------------------------------------------------
    # Здесь нужна ширина каждой метки, чтобы избежать наслаивания узлов.
    dummy_fig, dummy_ax = plt.subplots()
    dummy_fig.canvas.draw()  # инициализируем рендерер
    renderer = dummy_fig.canvas.get_renderer()

    # 4. Инициализация структур для хранения данных
    # --------------------------------------------
    node_labels = {}      # id(node) -> текст метки
    edges = []            # список рёбер (id_parent, id_child)
    visited_nodes = set() # чтобы не обрабатывать узел несколько раз

    # Расстояния между узлами
    y_spacing = 0.4       # вертикальный шаг между уровнями глубины
    x_spacing = 1.0       # минимальный горизонтальный отступ между листьями
    fontsize = 6          # размер шрифта для меток

    # 5. Функция для измерения ширины метки
    # -------------------------------------
    def measure_label_width(text):
        t = Text(text=text, fontsize=fontsize, fontfamily='monospace')
        t.set_figure(dummy_fig)
        # Получаем bounding box текста и переводим пиксели в дюймы
        bb = t.get_window_extent(renderer=renderer)
        return bb.width / dummy_fig.dpi

    # Хранение позиций узлов и счётчик X
    positions = {}  # id(node) -> (x, y)
    next_x = [0]    # список для изменения внутри вложенной функции

    # 6. Функция генерации текстовой метки узла
    # ----------------------------------------
    def get_label(node):
        # Для AST-узлов берём поля _fields: простые типы и списки примитивов
        if isinstance(node, ast.AST):
            fields = [(name, getattr(node, name)) for name in node._fields]
            parts = []
            for name, val in fields:
                if isinstance(val, (str, int, float)):
                    parts.append(f"{name}={val}")
                elif isinstance(val, list) and val and isinstance(val[0], (str, int, float)):
                    parts.append(f"{name}=[...]")
                # игнорируем None и сложные вложенные узлы
            label = node.__class__.__name__
            if parts:
                label += f"({', '.join(parts)})"
            return label
        # Для прочих объектов возвращаем строковое представление
        return str(node)

    # 7. Рекурсивное положение узлов
    # ------------------------------
    def assign_positions(node, depth=0):
        # Если узел уже был, выходим (избежание циклов)
        if id(node) in visited_nodes:
            return None
        visited_nodes.add(id(node))

        # Обрабатываем детей сначала, чтобы центрировать родителя над ними
        children = list(ast.iter_child_nodes(node))
        child_positions = []
        for child in children:
            pos = assign_positions(child, depth + 1)
            if pos:
                edges.append((id(node), id(child)))
                child_positions.append(pos)

        # Получаем метку и измеряем её ширину
        label = get_label(node)
        label_width = max(measure_label_width(label), 0.3)

        # X = среднее X детей или текущее next_x для листа
        if child_positions:
            x = sum(p[0] for p in child_positions) / len(child_positions)
        else:
            x = next_x[0]
            next_x[0] += label_width + x_spacing

        # Y определяется глубиной узла
        y = -depth * y_spacing
        positions[id(node)] = (x, y)
        node_labels[id(node)] = label
        return (x, y)

    # Запуск построения позиций от корня AST
    assign_positions(tree)

    # 8. Вычисление размеров итоговой фигуры
    xs, ys = zip(*positions.values())
    width = max(xs) - min(xs) + 1
    height = max(ys) - min(ys) + 1
    fig_width = max(10, width * 1.2)
    fig_height = max(6, height * 1.2)

    # 9. Отрисовка AST-графа
    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)  # без полей

    # 9.1. Рёбра
    for parent_id, child_id in edges:
        x1, y1 = positions[parent_id]
        x2, y2 = positions[child_id]
        ax.plot([x1, x2], [y1, y2], 'k-', lw=0.5, alpha=0.5)

    # 9.2. Узлы и метки
    for node_id, (x, y) in positions.items():
        ax.text(x, y, node_labels[node_id],
                ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.1', fc='lightblue', ec='black', lw=0.4),
                fontsize=fontsize, fontfamily='monospace')

    # 10. Настройка границ и сохранение результата
    ax.set_axis_off()
    ax.set_xlim(min(xs) - 0.5, max(xs) + 0.5)
    ax.set_ylim(min(ys) - 0.5, max(ys) + 0.5)
    plt.margins(0.01)

    plt.savefig(outpath, dpi=300, bbox_inches='tight')
    plt.close(fig)
    plt.close(dummy_fig)

    # Выводим информацию о сохранении
    print(f"AST structured visualization saved to {outpath}")


# ---------------- Analyzer Runner ---------------- #
def analyze_file(fpath, outpath):
    analyzer = ASTAnalyzer(fpath)
    with open(fpath, "r", encoding="utf-8") as f:
        tree_ast = ast.parse(f.read(), filename=fpath)
    analyzer.visit(tree_ast)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {"driver": {"name": "ast_tool", "rules": []}},
                "results": analyzer.issues,
            }
        ],
    }

    descriptions = {
        "USELESS_IF": "Condition is always true/false",
        "USE_OF_EVAL": "Potential code injection vulnerability",
        "USE_OF_EXEC": "Use of exec() detected, which can lead to code injection vulnerabilities",
        "LITERAL_IS": "Comparison using 'is' with literal values",
        "MISSING_RETURN_TYPE": "Missing function return type annotation",
    }

    for rid in {r["ruleId"] for r in analyzer.issues}:
        sarif["runs"][0]["tool"]["driver"]["rules"].append(
            {
                "id": rid,
                "shortDescription": {"text": rid},
                "fullDescription": {
                    "text": descriptions.get(rid, "No description available")
                },
            }
        )

    with open(outpath, "w", encoding="utf-8") as f:
        json.dump(sarif, f, ensure_ascii=False, indent=2)

    print(f"SARIF report written to {outpath}")


# ---------------- Entry Point ---------------- #
def main():
    args = parse_args()
    if args.parse:
        for fpath in args.parse:
            dump_ast(fpath)
    if args.visualize:
        visualize_ast(args.visualize[0], args.visualize[1])
    if args.analyze:
        analyze_file(args.analyze[0], args.analyze[1])


if __name__ == "__main__":
    main()
