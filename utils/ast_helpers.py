# utils/ast_helpers.py
import ast

def add_parent_links(tree: ast.AST):
    """Добавляет ссылки на родительские узлы для обхода AST"""
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            # безопасно добавляем атрибут parent
            try:
                child.parent = node
            except Exception:
                # на случай, если AST-узел не позволяет добавлять атрибуты
                pass
