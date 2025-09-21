def wrap(x):
    import html
    return html.escape(x) + "!"  # добавление данных после санитайза может быть опасно в некоторых sink'ах

a = wrap(request.args.get('u'))
render(a)  # CustomSanitizerAnalyzer пометит как 'unknown' или 'ineffective' в зависимости от heuristics
