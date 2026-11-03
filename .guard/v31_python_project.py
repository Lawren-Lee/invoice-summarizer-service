"""Static Python literal projection. Never import/execute repository modules."""
import ast
import json
import sys


def project(text, allowed, public_metadata=(), top_level_only=False):
    tree = ast.parse(text)
    allowed = dict(allowed)
    public_metadata=set(public_metadata)
    def permitted(name, value):
        return (isinstance(value, ast.Constant) and name in allowed
                and type(value.value) is type(allowed[name]) and value.value == allowed[name])
    allowed_nodes={id(n) for n in tree.body}
    found = []
    class Rewrite(ast.NodeTransformer):
        def visit_Assign(self, node):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            if (not top_level_only or id(node) in allowed_nodes) and len(names) == len(node.targets) and all(permitted(n, node.value) for n in names):
                return node
            return self.generic_visit(node)

        def visit_AnnAssign(self, node):
            if (not top_level_only or id(node) in allowed_nodes) and isinstance(node.target, ast.Name) and permitted(node.target.id, node.value):
                return node
            return self.generic_visit(node)

        def visit_Dict(self, node):
            # Keys are schema/metadata. Values still pass through projection.
            node.values = [self.visit(v) for v in node.values]
            return node

        def visit_Constant(self, node):
            if isinstance(node.value,str) and node.value in public_metadata:
                return node
            if isinstance(node.value, (str, bytes, int, float, complex, bool)):
                found.append(str(node.value))
                return ast.copy_location(ast.Constant(value="[REDACTED]"), node)
            return node
    assigned = {}
    for node in tree.body if top_level_only else ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            for target in node.targets:
                if isinstance(target, ast.Name): assigned[target.id] = node.value.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and isinstance(node.value, ast.Constant):
            assigned[node.target.id] = node.value.value
    # The caller checks assigned values against trusted schema before allowing.
    tree = Rewrite().visit(tree)
    ast.fix_missing_locations(tree)
    return {"text": ast.unparse(tree) + "\n", "discovered": found, "assigned": assigned}


if __name__ == "__main__":
    try:
        data = json.load(sys.stdin)
        if data.get("action") == "parse":
            result = project(data["text"], {}, top_level_only=data.get("top_level_only",False))
            result = {"assigned": result["assigned"]}
        else:
            result = project(data["text"], data.get("allowed", {}), data.get("public_metadata", []),data.get("top_level_only",False))
        print(json.dumps(result))
    except Exception:
        print(json.dumps({"error": "unsupported-or-invalid-python"}))
        sys.exit(1)
