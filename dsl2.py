from decimal import Decimal
from typing import Any, Callable

from lark import Lark, Transformer, UnexpectedInput, UnexpectedToken, v_args

from schemas import DSLError, DSLValidationResponse

dsl_grammar = """
    ?start: expr
    ?expr: or_expr
    ?or_expr: and_expr | or_expr "OR" and_expr -> or_expr
    ?and_expr: not_expr | and_expr "AND" not_expr -> and_expr
    ?not_expr: comparison
             | "NOT" not_expr -> not_expr
             | "(" expr ")"
    ?comparison: num_comparison | str_comparison
    num_comparison: num_field OP NUMBER
    str_comparison: str_field STR_OP SQ_STRING
    num_field: "amount" -> amount_field | "user.age" -> user_age_field
    str_field: "currency" -> currency_field | "merchantId" -> merchant_id_field 
             | "ipAddress" -> ip_address_field | "deviceId" -> device_id_field 
             | "user.region" -> user_region_field
    OP: ">=" | "<=" | ">" | "<" | "=" | "!="
    STR_OP: "=" | "!="
    SQ_STRING: /'[^']*'/
    %import common.NUMBER
    %import common.WS
    %ignore WS
"""


class DSLTransformer(Transformer):
    def amount_field(self, _):
        return lambda t, u: t.amount

    def user_age_field(self, _):
        return lambda t, u: Decimal(str(u.age)) if u.age is not None else None

    def currency_field(self, _):
        return lambda t, u: str(t.currency)

    def merchant_id_field(self, _):
        return lambda t, u: str(t.merchant_id)

    def ip_address_field(self, _):
        return lambda t, u: str(t.ip_address)

    def device_id_field(self, _):
        return lambda t, u: str(t.device_id)

    def user_region_field(self, _):
        return lambda t, u: str(u.region)

    @v_args(inline=True)
    def num_comparison(self, field_getter, op, value):
        val = Decimal(value.value)
        operator = op.value

        def compare(t, u):
            actual = field_getter(t, u)
            if actual is None:
                return False
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

    @v_args(inline=True)
    def str_comparison(self, field_getter, op, value):
        val = value.value[1:-1]
        operator = op.value

        def compare(t, u):
            actual = field_getter(t, u)
            if actual is None:
                return False
            actual_str = str(actual)
            return actual_str == val if operator == "=" else actual_str != val

        return compare

    def not_expr(self, items):
        inner = items[0]
        return lambda t, u: not inner(t, u)

    def and_expr(self, items):
        left, right = items[0], items[1]
        return lambda t, u: left(t, u) and right(t, u)

    def or_expr(self, items):
        left, right = items[0], items[1]
        return lambda t, u: left(t, u) or right(t, u)


_EXECUTOR = Lark(dsl_grammar, parser="lalr", transformer=DSLTransformer())
_VALIDATOR = Lark(dsl_grammar, parser="lalr")


def validate_dsl_logic(expression: str) -> DSLValidationResponse:
    try:
        _VALIDATOR.parse(expression)
        return DSLValidationResponse(
            isValid=True, normalizedExpression=expression.strip(), errors=[]
        )
    except (UnexpectedToken, UnexpectedInput) as e:
        start = max(0, e.column - 5)
        end = e.column + 5
        context = expression[start:end]
        return DSLValidationResponse(
            isValid=False,
            normalizedExpression=None,
            errors=[
                DSLError(
                    code="DSL_PARSE_ERROR",
                    message="Синтаксическая ошибка в выражении",
                    position=e.column,
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
