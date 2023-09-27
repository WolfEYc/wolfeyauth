import inspect
import aiosql


def get_module_source_code(module):
    source_code = ""
    for name, obj in inspect.getmembers(module):
        if inspect.isfunction(obj) or inspect.isclass(obj):
            source_code += inspect.getsource(obj) + "\n\n"
    return source_code


queries = aiosql.from_path("app/queries", "psycopg")

src = get_module_source_code(queries)

with open("queries.py", "w") as file:
    file.write(src)
