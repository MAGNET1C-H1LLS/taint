# utils/analyzer_loader.py
import os
import sys
import importlib
import inspect
from pathlib import Path
from typing import List, Type

def load_analyzers(analyzers_dir: str = "analyzers") -> List[Type]:
    """
    Динамически загружает все классы анализаторов (наследники BaseTaintAnalyzer)
    из указанной директории-пакета analyzers_dir.
    Возвращает список классов (не экземпляров).
    """
    analyzers_classes = []

    # Путь к проекту (директория, где находится utils/)
    current_dir = Path(__file__).parent.parent.resolve()
    analyzers_path = (current_dir / analyzers_dir).resolve()

    if not analyzers_path.exists():
        print(f"[analyzer_loader] Директория {analyzers_path} не существует!")
        return analyzers_classes

    # Убедимся, что parent директория находится в sys.path, чтобы можно было импортировать пакет
    project_root = str(current_dir)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # Импортируем базовый класс для isinstance/issubclass
    try:
        base_module = importlib.import_module(f"{analyzers_dir}.base_analyzer")
        BaseTaintAnalyzer = getattr(base_module, "BaseTaintAnalyzer")
    except Exception as e:
        print(f"[analyzer_loader] Не удалось импортировать base_analyzer: {e}")
        return analyzers_classes

    # Перебираем .py файлы в пакете (игнорируем __init__ и приватные)
    for file_path in analyzers_path.glob("*.py"):
        name = file_path.stem
        if name.startswith("_") or name in ("__init__", "base_analyzer"):
            continue

        full_module_name = f"{analyzers_dir}.{name}"
        try:
            if full_module_name in sys.modules:
                module = importlib.reload(sys.modules[full_module_name])
            else:
                module = importlib.import_module(full_module_name)
        except Exception as e:
            print(f"[analyzer_loader] Ошибка загрузки модуля {full_module_name}: {e}")
            continue

        # Ищем классы-подклассы BaseTaintAnalyzer (не сам BaseTaintAnalyzer)
        for _, obj in inspect.getmembers(module, inspect.isclass):
            # obj может быть импортирован из base_analyzer — проверяем принадлежность модулю
            try:
                if obj is BaseTaintAnalyzer:
                    continue
                if issubclass(obj, BaseTaintAnalyzer):
                    analyzers_classes.append(obj)
                    print(f"[analyzer_loader] Загружен анализатор: {obj.__name__} (из {full_module_name})")
            except Exception:
                # Если obj не связан с BaseTaintAnalyzer — пропускаем
                continue

    # Сортируем по имени для детерминированности
    analyzers_classes.sort(key=lambda cls: cls.__name__)
    return analyzers_classes
