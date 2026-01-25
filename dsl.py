from decimal import Decimal
from typing import Any

from lark import Lark, Transformer
from lark.exceptions import UnexpectedInput, VisitError

from schemas import DSLError, DSLValidationResponse

DSL_GRAMMAR = r"""
    ?start: expression

    ?expression: term
               | expression "OR"i term  -> binary_or

    ?term: factor
         | term "AND"i factor       -> binary_and

    ?factor: "NOT"i factor          -> unary_not
           | comparison
           | "(" expression ")"

    comparison: field operator value

    !field: CNAME ("." CNAME)?
    
    operator: GREATER_EQUALS | LESS_EQUALS | GREATER | LESS | EQUALS | NOT_EQUALS

    value: NUMBER      -> number_val
         | SQ_STRING   -> string_val

    GREATER_EQUALS: ">="
    LESS_EQUALS: "<="
    GREATER: ">"
    LESS: "<"
    EQUALS: "="
    NOT_EQUALS: "!="

    SQ_STRING: /'[^']*'/
    
    %import common.CNAME
    %import common.NUMBER
    %import common.WS
    %ignore WS
"""

FIELD_METADATA = {
    "amount": "number",
    "currency": "string",
    "merchantId": "string",
    "ipAddress": "string",
    "deviceId": "string",
    "user.age": "number",
    "user.region": "string",
}


class DSLSemanticError(Exception):
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message


class DSLValidator(Transformer):
    def field(self, items):
        field_name = "".join(item.value for item in items)
        if field_name not in FIELD_METADATA:
            raise DSLSemanticError("DSL_INVALID_FIELD", f"Unknown field: {field_name}")
        return field_name

    def operator(self, items):
        return items[0].value

    def number_val(self, items):
        return items[0].value, "number"

    def string_val(self, items):
        return items[0].value, "string"

    def comparison(self, items):
        field_name = items[0]
        op = items[1]
        val_str, val_type = items[2]

        field_type = FIELD_METADATA[field_name]

        if field_type != val_type:
            raise DSLSemanticError(
                "DSL_INVALID_OPERATOR",
                f"Type mismatch: {field_name} is {field_type}, value is {val_type}",
            )

        if field_type == "string" and op not in ("=", "!="):
            raise DSLSemanticError(
                "DSL_INVALID_OPERATOR", f"Operator {op} not allowed for string fields"
            )

        return f"{field_name} {op} {val_str}", 3

    def unary_not(self, items):
        expr, prio = items[0]
        if prio < 2:
            return f"NOT ({expr})", 2
        return f"NOT {expr}", 2

    def binary_and(self, items):
        left, left_prio = items[0]
        right, right_prio = items[1]

        l_str = f"({left})" if left_prio < 1 else left
        r_str = f"({right})" if right_prio < 1 else right
        return f"{l_str} AND {r_str}", 1

    def binary_or(self, items):
        left, left_prio = items[0]
        right, right_prio = items[1]

        l_str = f"({left})" if left_prio < 0 else left
        r_str = f"({right})" if right_prio < 0 else right
        return f"{l_str} OR {r_str}", 0


class DSLEvaluator(Transformer):
    def __init__(self, transaction: Any, user: Any):
        self.transaction = transaction
        self.user = user

    def field(self, items):
        return "".join(item.value for item in items)

    def operator(self, items):
        return items[0].value

    def number_val(self, items):
        return Decimal(items[0].value)

    def string_val(self, items):
        return items[0].value[1:-1]

    def comparison(self, items):
        field_name, op, val = items
        actual_value = None

        if "." in field_name:
            parts = field_name.split(".")
            prefix = parts[0]
            attr = parts[1]
            if prefix == "user" and self.user:
                actual_value = getattr(self.user, attr, None)
        else:
            mapping = {
                "deviceId": "device_id",
                "merchantId": "merchant_id",
                "ipAddress": "ip_address",
                "merchantCategoryCode": "merchant_category_code",
            }
            attr_name = mapping.get(field_name, field_name)
            actual_value = getattr(self.transaction, attr_name, None)

        print(f"[DSL_STEP 2] DB Value: {actual_value} (Type: {type(actual_value)})")

        if actual_value is None:
            return False

        if isinstance(val, (Decimal, int, float)):
            try:
                v1 = Decimal(str(actual_value))
                v2 = Decimal(str(val))

                if op == ">":
                    res = v1 > v2
                elif op == ">=":
                    res = v1 >= v2
                elif op == "<":
                    res = v1 < v2
                elif op == "<=":
                    res = v1 <= v2
                elif op == "=":
                    res = v1 == v2
                elif op == "!=":
                    res = v1 != v2
                else:
                    res = False
                return res
            except Exception:
                return False

        res = False
        if op == "=":
            res = str(actual_value) == str(val)
        elif op == "!=":
            res = str(actual_value) != str(val)
        return res

    def unary_not(self, items):
        return not items[0]

    def binary_and(self, items):
        return items[0] and items[1]

    def binary_or(self, items):
        return items[0] or items[1]


_PARSER = Lark(DSL_GRAMMAR, parser="lalr")


def validate_rule(expression: str) -> DSLValidationResponse:
    if not expression or not expression.strip():
        return DSLValidationResponse(
            isValid=False,
            errors=[DSLError(code="DSL_PARSE_ERROR", message="Empty expression")],
        )

    try:
        tree = _PARSER.parse(expression)
        normalized, _ = DSLValidator().transform(tree)
        return DSLValidationResponse(
            isValid=True, normalizedExpression=normalized, errors=[]
        )

    except UnexpectedInput as e:
        return DSLValidationResponse(
            isValid=False,
            errors=[
                DSLError(
                    code="DSL_PARSE_ERROR",
                    message="Syntax error",
                    position=e.column,
                    near=e.get_context(expression, span=5),
                )
            ],
        )
    except VisitError as e:
        orig = e.orig_exc
        if isinstance(orig, DSLSemanticError):
            return DSLValidationResponse(
                isValid=False, errors=[DSLError(code=orig.code, message=orig.message)]
            )
        return DSLValidationResponse(
            isValid=False, errors=[DSLError(code="DSL_PARSE_ERROR", message=str(orig))]
        )
    except Exception as e:
        return DSLValidationResponse(
            isValid=False, errors=[DSLError(code="DSL_PARSE_ERROR", message=str(e))]
        )


def evaluate_rule(expression: str, transaction: Any, user: Any) -> bool:
    try:
        if not expression or not expression.strip():
            return False
        tree = _PARSER.parse(expression)
        return bool(DSLEvaluator(transaction, user).transform(tree))
    except Exception:
        return False
