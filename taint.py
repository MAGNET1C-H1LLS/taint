import ast
import matplotlib.pyplot as plt
from matplotlib.text import Text

# переделать

def visualize_ast(fpath, outpath):
    """
    Парсит Python-файл и строит визуализацию его AST с динамическим и компактным раскладом по X,
    пропуская повторные ссылки на одни и те же узлы, чтобы избежать перекрестных связей.
    """

    # 1. Чтение и парсинг исходного кода в AST
    with open(fpath, 'r', encoding='utf-8') as f:
        src = f.read()
    tree = ast.parse(src, filename=fpath)

    # 2. Подготовка "манекена" для измерения ширины текста
    dummy_fig, _ = plt.subplots()
    dummy_fig.canvas.draw()
    renderer = dummy_fig.canvas.get_renderer()

    # Настройки визуализации
    fontsize = 6
    x_spacing = 0.3  # Минимальный горизонтальный отступ между поддеревьями
    y_spacing = 0.6  # Вертикальное расстояние между уровнями AST

    # 3. Функция измерения ширины текстовой метки узла
    def measure_label(text):
        t = Text(text=text, fontsize=fontsize, fontfamily='monospace')
        t.set_figure(dummy_fig)
        bb = t.get_window_extent(renderer=renderer)
        return bb.width / dummy_fig.dpi

    # Словари для хранения информации об AST
    labels = {}           # id(node) -> текстовая метка
    subtree_width = {}    # id(node) -> ширина поддерева
    seen_nodes = set()    # множество уже посещённых узлов для подсчёта ширины

    # 4. Генерация текста метки для узла AST
    def get_label(node):
        if isinstance(node, ast.AST):
            parts = []
            for name in node._fields:
                val = getattr(node, name)
                if isinstance(val, (str, int, float)):
                    parts.append(f"{name}={val}")
                elif isinstance(val, list) and val and isinstance(val[0], (str, int, float)):
                    parts.append(f"{name}=[...]")
            label = node.__class__.__name__
            if parts:
                label += f"({', '.join(parts)})"
            return label
        return str(node)

    # 5. Рекурсивный подсчёт ширины поддерева
    def compute_width(node):
        if id(node) in subtree_width:
            return subtree_width[id(node)]

        lbl = get_label(node)
        labels[id(node)] = lbl
        w_lbl = measure_label(lbl)

        # Отфильтровываем уже посещённые дочерние узлы, чтобы избежать повторов
        children = [ch for ch in ast.iter_child_nodes(node)]
        children = [ch for ch in children if id(ch) not in seen_nodes]
        for ch in children:
            seen_nodes.add(id(ch))

        if not children:
            subtree_width[id(node)] = w_lbl
            return w_lbl

        total = sum(compute_width(ch) for ch in children)
        total += x_spacing * (len(children) - 1)
        subtree_width[id(node)] = max(w_lbl, total)
        return subtree_width[id(node)]

    # Подсчёт ширины для корня дерева
    compute_width(tree)

    positions = {}  # id(node) -> (x, y)
    edges = []      # (parent_id, child_id)

    # 6. Рекурсивное размещение узлов на координатной плоскости
    def assign(node, x_start, depth=0):
        w = subtree_width[id(node)]
        x_c = x_start + w / 2  # Центр текущего узла
        y = -depth * y_spacing
        positions[id(node)] = (x_c, y)

        children = [ch for ch in ast.iter_child_nodes(node)]
        children = [ch for ch in children if id(ch) not in positions]  # Только новые узлы

        curr = x_start
        for ch in children:
            edges.append((id(node), id(ch)))
            assign(ch, curr, depth + 1)
            curr += subtree_width[id(ch)] + x_spacing

    # Запуск построения позиций от корня
    assign(tree, x_start=0)

    # 7. Подготовка и отрисовка графа
    xs, ys = zip(*positions.values())
    fig_w = max(8, max(xs) - min(xs) + 1)
    fig_h = max(5, max(ys) - min(ys) + 1)
    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)

    # Рисуем рёбра
    for p, c in edges:
        x1, y1 = positions[p]
        x2, y2 = positions[c]
        ax.plot([x1, x2], [y1, y2], '-', lw=0.5, alpha=0.6)

    # Рисуем узлы
    for nid, (x, y) in positions.items():
        ax.text(x, y, labels[nid], ha='center', va='center',
                bbox=dict(boxstyle='round,pad=0.1', fc='lightblue', ec='black', lw=0.4),
                fontsize=fontsize, fontfamily='monospace')

    # Убираем оси и сохраняем изображение
    ax.set_axis_off()
    ax.set_xlim(min(xs) - 0.5, max(xs) + 0.5)
    ax.set_ylim(min(ys) - 0.5, max(ys) + 0.5)
    plt.margins(0.01)

    plt.savefig(outpath, dpi=300, bbox_inches='tight')
    plt.close(fig)
    plt.close(dummy_fig)
    print(f"AST visualization saved to {outpath}")
