from decimal import Decimal
from typing import Any, Callable

from lark import Lark, Transformer, UnexpectedInput, UnexpectedToken, v_args
from lark.exceptions import VisitError

from schemas import DSLError, DSLValidationResponse

dsl_grammar = """
    ?start: expr
    ?expr: or_expr
    ?or_expr: and_expr | or_expr "OR" and_expr -> or_expr
    ?and_expr: not_expr | and_expr "AND" not_expr -> and_expr
    ?not_expr: comparison
             | "NOT" not_expr -> not_expr
             | "(" expr ")"
    
    comparison: field OP value

    field: CNAME | CNAME "." CNAME
    
    ?value: NUMBER -> num_val 
          | SQ_STRING -> str_val

    OP: ">=" | "<=" | ">" | "<" | "=" | "!="
    SQ_STRING: /'[^']*'/
    
    %import common.CNAME
    %import common.NUMBER
    %import common.WS
    %ignore WS
"""

FIELD_CONFIG = {
    "amount": {"type": "number"},
    "user.age": {"type": "number"},
    "currency": {"type": "string"},
    "merchantId": {"type": "string"},
    "ipAddress": {"type": "string"},
    "deviceId": {"type": "string"},
    "user.region": {"type": "string"},
}


class DSLSemanticError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


class DSLTransformer(Transformer):
    def __init__(self, check_semantics=False):
        self.check_semantics = check_semantics

    def field(self, items):
        return "".join(t.value for t in items)

    def num_val(self, items):
        return Decimal(items[0]), "number"

    def str_val(self, items):
        return items[0][1:-1], "string"

    @v_args(inline=True)
    def comparison(self, field_name, op, value_tuple):
        val, val_type = value_tuple
        operator = op.value

        if self.check_semantics:
            if field_name not in FIELD_CONFIG:
                raise DSLSemanticError(
                    "DSL_INVALID_FIELD", f"Unknown field: {field_name}"
                )

            field_type = FIELD_CONFIG[field_name]["type"]

            if field_type == "string" and operator not in ("=", "!="):
                raise DSLSemanticError(
                    "DSL_INVALID_OPERATOR",
                    f"Operator {operator} not allowed for string field {field_name}",
                )

            if field_type != val_type:
                raise DSLSemanticError(
                    "DSL_INVALID_OPERATOR",
                    f"Cannot compare {field_type} field with {val_type} value",
                )

            return True

        getters = {
            "amount": lambda t, u: t.amount,
            "user.age": lambda t, u: Decimal(u.age)
            if getattr(u, "age", None) is not None
            else None,
            "currency": lambda t, u: str(t.currency),
            "merchantId": lambda t, u: getattr(t, "merchant_id", None),
            "ipAddress": lambda t, u: getattr(t, "ip_address", None),
            "deviceId": lambda t, u: getattr(t, "device_id", None),
            "user.region": lambda t, u: getattr(u, "region", None),
        }

        getter = getters.get(field_name, lambda t, u: None)

        def compare(t, u):
            actual = getter(t, u)
            if actual is None:
                return False

            if val_type == "string":
                actual = str(actual)

            if operator == ">":
                return actual > val
            if operator == ">=":
                return actual >= val
            if operator == "<":
                return actual < val
            if operator == "<=":
                return actual <= val
            if operator == "=":
                return actual == val
            if operator == "!=":
                return actual != val
            return False

        return compare

    def not_expr(self, items):
        if self.check_semantics:
            return True
        inner = items[0]
        return lambda t, u: not inner(t, u)

    def and_expr(self, items):
        if self.check_semantics:
            return True
        left, right = items[0], items[1]
        return lambda t, u: left(t, u) and right(t, u)

    def or_expr(self, items):
        if self.check_semantics:
            return True
        left, right = items[0], items[1]
        return lambda t, u: left(t, u) or right(t, u)


_VALIDATOR = Lark(
    dsl_grammar, parser="lalr", transformer=DSLTransformer(check_semantics=True)
)
_EXECUTOR = Lark(
    dsl_grammar, parser="lalr", transformer=DSLTransformer(check_semantics=False)
)


def validate_dsl_logic(expression: str) -> DSLValidationResponse:
    if not expression or not expression.strip():
        return DSLValidationResponse(
            isValid=False,
            normalizedExpression=None,
            errors=[DSLError(code="DSL_PARSE_ERROR", message="Empty expression")],
        )

    try:
        _VALIDATOR.parse(expression)
        return DSLValidationResponse(
            isValid=True, normalizedExpression=expression.strip(), errors=[]
        )

    except VisitError as e:
        orig = e.orig_exc
        code = orig.code if isinstance(orig, DSLSemanticError) else "DSL_INTERNAL_ERROR"
        return DSLValidationResponse(
            isValid=False,
            normalizedExpression=None,
            errors=[DSLError(code=code, message=str(orig))],
        )

    except (UnexpectedToken, UnexpectedInput) as e:
        col = getattr(e, "column", 0) or 0
        context = expression[max(0, col - 5) : col + 5]
        return DSLValidationResponse(
            isValid=False,
            normalizedExpression=None,
            errors=[
                DSLError(
                    code="DSL_PARSE_ERROR",
                    message="Syntax Error",
                    position=col,
                    near=context.strip(),
                )
            ],
        )
    except Exception as e:
        return DSLValidationResponse(
            isValid=False,
            normalizedExpression=None,
            errors=[DSLError(code="DSL_INTERNAL_ERROR", message=str(e))],
        )


async def evaluate_rule(dsl_expression: str, transaction: Any, user: Any) -> bool:
    try:
        if not dsl_expression or not dsl_expression.strip():
            return False
        rule_func: Callable = _EXECUTOR.parse(dsl_expression)
        return rule_func(transaction, user)
    except Exception:
        return False
