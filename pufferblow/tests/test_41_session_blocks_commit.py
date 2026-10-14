"""Every `with ...database_session() as s:` block that writes must commit.

`database_session` is a plain sessionmaker: closing the block without `s.commit()` silently
rolls the writes back (three such bugs were found by hand). This static check reads the source
so a new one fails here instead of in production.

A block counts as writing when it calls `s.add/add_all/delete/merge/bulk_*`, executes an
`update/insert/delete` statement (inline, or one built earlier in the same function), runs
`query(...).update()/.delete()`, or assigns to an attribute of an object it loaded. It counts as
committing when it calls `s.commit()` after its last write, or uses `s.begin()`.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parents[1]
WRITE_METHODS = {"add", "add_all", "delete", "merge", "bulk_save_objects", "bulk_insert_mappings", "bulk_update_mappings"}
WRITE_STATEMENTS = {"update", "insert", "delete", "pg_insert", "sqlite_insert"}


def _root_call(node: ast.AST) -> ast.AST:
    """`update(T).where(...).values(...)` -> the `update(T)` call."""
    while isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        node = node.func.value
    return node


def _name_of_call(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        func = node.func
        return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else None
    return None


def _session_call(node: ast.AST, session: str, *methods: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in methods
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == session
    )


def _statement_kinds(function: ast.AST) -> dict[str, str | None]:
    """What each `stmt = ...` in a function builds (`stmt = stmt.where(...)` keeps its kind)."""
    kinds: dict[str, str | None] = {}
    assigns = [n for n in ast.walk(function) if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)]
    for assign in sorted(assigns, key=lambda n: n.lineno):
        name = assign.targets[0].id
        root = _root_call(assign.value)
        if isinstance(root, ast.Name) and root.id == name:
            continue
        kinds[name] = _name_of_call(root)
    return kinds


def _block_problems(session: str, body: list[ast.stmt], kinds: dict[str, str | None]) -> str | None:
    writes: list[int] = []
    commits: list[int] = []
    loaded: set[str] = set()

    for node in (n for stmt in body for n in ast.walk(stmt)):
        if _session_call(node, session, "begin", "begin_nested"):
            return None
        if _session_call(node, session, "commit"):
            commits.append(node.lineno)
        elif _session_call(node, session, *WRITE_METHODS):
            writes.append(node.lineno)
        elif _session_call(node, session, "execute") and node.args:
            arg = node.args[0]
            kind = kinds.get(arg.id) if isinstance(arg, ast.Name) else _name_of_call(_root_call(arg))
            if kind in WRITE_STATEMENTS:
                writes.append(node.lineno)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"update", "delete"}:
            if any(_session_call(n, session, "query") for n in ast.walk(node.func.value)):
                writes.append(node.lineno)
        elif isinstance(node, (ast.Assign, ast.For)):
            source = node.value if isinstance(node, ast.Assign) else node.iter
            if any(isinstance(n, ast.Name) and (n.id == session or n.id in loaded) for n in ast.walk(source)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                loaded.update(n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name))
        if isinstance(node, (ast.Assign, ast.AugAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                root = target
                while isinstance(root, (ast.Attribute, ast.Subscript)):
                    root = root.value
                if isinstance(target, ast.Attribute) and isinstance(root, ast.Name) and root.id in loaded and root.id != "self":
                    writes.append(node.lineno)

    if not writes:
        return None
    if not commits:
        return "writes without committing"
    if max(writes) > max(commits):
        return f"writes at line {max(writes)} after its last commit (line {max(commits)})"
    return None


def _find_problems() -> list[str]:
    problems = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if "tests" in path.parts or "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for function in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
            kinds = None
            for node in ast.walk(function):
                if not isinstance(node, (ast.With, ast.AsyncWith)):
                    continue
                for item in node.items:
                    ctx = item.context_expr
                    is_db_session = isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Attribute) and ctx.func.attr == "database_session"
                    if not is_db_session or not isinstance(item.optional_vars, ast.Name):
                        continue
                    session = item.optional_vars.id
                    if any(_session_call(i.context_expr, session, "begin") for i in node.items):
                        continue
                    kinds = kinds if kinds is not None else _statement_kinds(function)
                    problem = _block_problems(session, node.body, kinds)
                    if problem:
                        problems.append(f"{path.relative_to(PACKAGE)}:{node.lineno} {function.name}: {problem}")
    # A with-block inside a nested function is seen from both functions; report it once.
    return sorted(set(problems))


def test_every_session_block_that_writes_commits():
    problems = _find_problems()
    assert not problems, "Session blocks that lose their writes:\n" + "\n".join(problems)


@pytest.mark.parametrize(
    "source, expected",
    [
        ("with self.database_session() as s:\n    s.add(x)\n", "writes without committing"),
        ("with self.database_session() as s:\n    row = s.get(T, 1)\n    row.name = 'a'\n", "writes without committing"),
        ("with self.database_session() as s:\n    stmt = update(T).values(a=1)\n    s.execute(stmt)\n", "writes without committing"),
        ("with self.database_session() as s:\n    s.commit()\n    s.add(x)\n", "after its last commit"),
        ("with self.database_session() as s:\n    s.add(x)\n    s.commit()\n", None),
        ("with self.database_session() as s, s.begin():\n    s.add(x)\n", None),
        ("with self.database_session() as s:\n    stmt = select(T)\n    stmt = stmt.where(T.a == 1)\n    return s.execute(stmt).all()\n", None),
    ],
)
def test_the_check_itself(source, expected, tmp_path, monkeypatch):
    module = tmp_path / "pkg" / "mod.py"
    module.parent.mkdir()
    module.write_text("def f(self):\n" + "".join(f"    {line}\n" for line in source.splitlines()), encoding="utf-8")
    monkeypatch.setattr(__import__(__name__), "PACKAGE", tmp_path / "pkg")
    problems = _find_problems()
    if expected is None:
        assert problems == []
    else:
        assert len(problems) == 1 and expected in problems[0]
