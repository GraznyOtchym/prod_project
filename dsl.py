from decimal import Decimal
from typing import Any

from lark import Lark, Transformer, UnexpectedInput, UnexpectedToken
from lark.exceptions import VisitError

from schemas import DSLError, DSLValidationResponse

dsl_grammar = r"""
    ?start: expr

    ?expr: or_expr

    ?or_expr: and_expr
            | or_expr OR and_expr

    ?and_expr: not_expr
             | and_expr AND not_expr

    ?not_expr: comparison
             | NOT not_expr
             | "(" expr ")"

    comparison: field OP value

    field: CNAME ("." CNAME)?

    ?value: NUMBER      -> num_val
          | SQ_STRING   -> str_val

    OP: ">=" | "<=" | ">" | "<" | "=" | "!="
    
    SQ_STRING: /'[^']*'/
    
    OR: "OR"i
    AND: "AND"i
    NOT: "NOT"i

    %import common.CNAME
    %import common.NUMBER
    %import common.WS
    %ignore WS
"""


class DSLEvaluator(Transformer):
    def field(self, items):
        return "".join(str(i) for i in items)

    def num_val(self, items):
        return Decimal(items[0])

    def str_val(self, items):
        return items[0][1:-1]

    def comparison(self, items):
        field_name, op, val = items[0], items[1].value, items[2]

        def get_value(tx, user):
            if field_name == "amount":
                return getattr(tx, "amount", 0)
            if field_name == "currency":
                return getattr(tx, "currency", "")
            if field_name == "merchantId":
                return getattr(tx, "merchant_id", "")
            if field_name == "ipAddress":
                return getattr(tx, "ip_address", "")
            if field_name == "deviceId":
                return getattr(tx, "device_id", "")
            if field_name == "user.age":
                return getattr(user, "age", 0)
            if field_name == "user.region":
                return getattr(user, "region", "")
            return None

        def compare(tx, user):
            actual = get_value(tx, user)
            if actual is None:
                return False

            if isinstance(val, Decimal) and not isinstance(actual, Decimal):
                try:
                    actual = Decimal(str(actual))
                except Exception:
                    return False

            if op == ">":
                return actual > val
            if op == ">=":
                return actual >= val
            if op == "<":
                return actual < val
            if op == "<=":
                return actual <= val
            if op == "=":
                return actual == val
            if op == "!=":
                return actual != val
            return False

        return compare

    def unary_not(self, items):
        inner_func = items[0]
        return lambda tx, user: not inner_func(tx, user)

    def binary_and(self, items):
        left, right = items[0], items[1]
        return lambda tx, user: left(tx, user) and right(tx, user)

    def binary_or(self, items):
        left, right = items[0], items[1]
        return lambda tx, user: left(tx, user) or right(tx, user)

    def start(self, items):
        return items[0]


_EXECUTOR_PARSER = Lark(dsl_grammar, parser="lalr", transformer=DSLEvaluator())


FIELD_TYPES = {
    "amount": "number",
    "currency": "string",
    "merchantId": "string",
    "ipAddress": "string",
    "deviceId": "string",
    "user.age": "number",
    "user.region": "string",
}


class DSLSemanticError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


class DSLValidator(Transformer):
    # Каждое правило возвращает кортеж: (нормализованная_строка, приоритет)
    # Приоритеты: OR=0, AND=1, NOT=2, Comparison=3

    def field(self, items):
        name = "".join(str(i) for i in items)
        if name not in FIELD_TYPES:
            raise DSLSemanticError("DSL_INVALID_FIELD", f"Unknown field: {name}")
        return name

    def num_val(self, items):
        return str(items[0]), "number"

    def str_val(self, items):
        return items[0], "string"  # Возвращаем с кавычками

    def comparison(self, items):
        f_name = items[0]
        op = items[1].value
        val_str, val_type = items[2]

        f_type = FIELD_TYPES[f_name]

        # Проверка DSL_INVALID_OPERATOR по ТЗ
        if f_type == "string" and op not in ("=", "!="):
            raise DSLSemanticError(
                "DSL_INVALID_OPERATOR", f"Strings don't support {op}"
            )

        if f_type != val_type:
            raise DSLSemanticError(
                "DSL_INVALID_OPERATOR", f"Type mismatch: {f_type} vs {val_type}"
            )

        # Нормализация: пробелы вокруг оператора по ТЗ
        return f"{f_name} {op} {val_str}", 3

    def or_expr(self, items):
        # Если это цепочка OR
        parts = []
        for item in items:
            # Для OR скобки внутри не нужны, если там AND или Comparison
            parts.append(item[0])
        return " OR ".join(parts), 0

    def and_expr(self, items):
        parts = []
        for item in items:
            text, priority = item
            # Если внутри AND находится OR (priority 0), нужны скобки
            parts.append(f"({text})" if priority < 1 else text)
        return " AND ".join(parts), 1

    def unary_not(self, items):
        text, priority = items[0]
        # Если внутри NOT находится AND или OR, нужны скобки
        res = f"NOT ({text})" if priority < 2 else f"NOT {text}"
        return res, 2

    def start(self, items):
        return items[0][0]


_PARSER = Lark(dsl_grammar, parser="lalr")


def validate_dsl_logic(expression: str) -> DSLValidationResponse:
    if not expression or not expression.strip():
        return DSLValidationResponse(
            isValid=False,
            errors=[
                DSLError(
                    code="DSL_PARSE_ERROR",
                    message="Empty expression",
                    position=0,
                    near="",
                )
            ],
        )

    try:
        # 1. Синтаксический анализ
        tree = _PARSER.parse(expression)

        # 2. Семантика и нормализация через Transformer
        normalized = DSLValidator().transform(tree)

        return DSLValidationResponse(
            isValid=True, normalizedExpression=normalized, errors=[]
        )

    except (UnexpectedToken, UnexpectedInput) as e:
        # Ошибка синтаксиса (DSL_PARSE_ERROR)
        col = getattr(e, "column", 0)
        return DSLValidationResponse(
            isValid=False,
            errors=[
                DSLError(
                    code="DSL_PARSE_ERROR",
                    message="Syntax error",
                    position=col,
                    near=expression[max(0, col - 5) : col + 5],
                )
            ],
        )

    except VisitError as e:
        # Ошибки из Трансформера (Field и Operator)
        orig = e.orig_exc
        if isinstance(orig, DSLSemanticError):
            return DSLValidationResponse(
                isValid=False, errors=[DSLError(code=orig.code, message=orig.message)]
            )
        return DSLValidationResponse(
            isValid=False,
            errors=[DSLError(code="DSL_INTERNAL_ERROR", message=str(orig))],
        )

    except Exception as e:
        return DSLValidationResponse(
            isValid=False, errors=[DSLError(code="DSL_INTERNAL_ERROR", message=str(e))]
        )


async def evaluate_rule(dsl_expression: str, transaction: Any, user: Any) -> bool:
    try:
        if not dsl_expression or not dsl_expression.strip():
            return False

        rule_func = _EXECUTOR_PARSER.parse(dsl_expression)

        return bool(rule_func(transaction, user))
    except Exception:
        return False
