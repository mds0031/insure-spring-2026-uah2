import sys
import pickle


def print_help():
    print("Python script that dumps a pickled D4M associative array for this project")
    print("Usage:")
    print("\tpython adump.py {assoc.pkl file}")
    print("Examples:")
    print("\tpython adump.py layer7_string_all.assoc.pkl")
    print("\tpython adump.py 0.assoc.pkl")


def load_assoc_from_pkl(filename):
    with open(filename, "rb") as f:
        return pickle.load(f)


def _to_list_if_possible(value):
    try:
        return list(value)
    except Exception:
        return None


def try_find_triples(A):
    """
    Best-effort extraction of row/col/value triples from a D4M Assoc object.
    Tries common attribute names and a few method-style access patterns.
    """
    # Common attribute name combinations
    attr_sets = [
        ("row", "col", "val"),
        ("rows", "cols", "vals"),
        ("r", "c", "v"),
    ]

    for row_name, col_name, val_name in attr_sets:
        if hasattr(A, row_name) and hasattr(A, col_name) and hasattr(A, val_name):
            rows = _to_list_if_possible(getattr(A, row_name))
            cols = _to_list_if_possible(getattr(A, col_name))
            vals = _to_list_if_possible(getattr(A, val_name))
            if rows is not None and cols is not None and vals is not None:
                if len(rows) == len(cols) == len(vals):
                    return rows, cols, vals, f"attributes {row_name}/{col_name}/{val_name}"

    # Common method-style possibilities
    method_sets = [
        ("find",),
        ("triples",),
        ("to_triples",),
    ]

    for methods in method_sets:
        for method_name in methods:
            if hasattr(A, method_name) and callable(getattr(A, method_name)):
                try:
                    result = getattr(A, method_name)()
                    if isinstance(result, tuple) and len(result) == 3:
                        rows = _to_list_if_possible(result[0])
                        cols = _to_list_if_possible(result[1])
                        vals = _to_list_if_possible(result[2])
                        if rows is not None and cols is not None and vals is not None:
                            if len(rows) == len(cols) == len(vals):
                                return rows, cols, vals, f"method {method_name}()"
                except Exception:
                    pass

    return None, None, None, None


def truncate(text, max_len=80):
    text = str(text)
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def dump_clean_triples(A, max_label_len=40):
    rows, cols, vals, source = try_find_triples(A)
    if rows is None:
        return False

    print("Loaded object type:", type(A).__name__)
    print("Recovered triples using", source)
    print("-" * 80)

    total = 0

    for r, c, v in zip(rows, cols, vals):
        r = str(r)
        c = truncate(c, max_label_len)
        v = str(v)

        try:
            total += int(float(v))
        except Exception:
            pass

        print(f"row: {r}")
        print(f"col: {c}")
        print(f"val: {v}")
        print("-" * 80)

    print("total observations:", total)
    return True


def fallback_printfull(A):
    print("Loaded object type:", type(A).__name__)
    print("Could not recover triples directly; falling back to D4M printfull().")
    if hasattr(A, "printfull") and callable(A.printfull):
        A.printfull()
        return

    print("No printfull() available.")
    print("Available attributes:")
    for name in sorted(n for n in dir(A) if not n.startswith("__")):
        print(" ", name)
    print("\nObject repr:")
    print(A)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print_help()
        sys.exit(1)

    assoc_file = sys.argv[1]

    try:
        A = load_assoc_from_pkl(assoc_file)
        if not dump_clean_triples(A):
            fallback_printfull(A)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)