import re
from decimal import Decimal
from typing import Any


async def evaluate_rule(dsl_expression: str, transaction: Any, user: Any) -> bool:
    while "(" in dsl_expression:
        match = re.search(r"\(([^()]+)\)", dsl_expression)
        if not match:
            break

        inner_content = match.group(1)

        inner_result = await evaluate_rule(inner_content, transaction, user)

        start, end = match.span()
        dsl_expression = (
            dsl_expression[:start] + str(inner_result).upper() + dsl_expression[end:]
        )

    or_parts = re.split(r"\s+OR\s+", dsl_expression, flags=re.IGNORECASE)
    if len(or_parts) > 1:
        for block in or_parts:
            if await evaluate_rule(block, transaction, user):
                return True
        return False

    and_parts = re.split(r"\s+AND\s+", dsl_expression, flags=re.IGNORECASE)
    if len(and_parts) > 1:
        for block in and_parts:
            if not await evaluate_rule(block, transaction, user):
                return False
        return True

    dsl_expression = dsl_expression.strip()
    if dsl_expression.upper().startswith("NOT "):
        inner_dsl = dsl_expression[4:].strip()
        return not await evaluate_rule(inner_dsl, transaction, user)

    if dsl_expression.upper() == "TRUE":
        return True
    if dsl_expression.upper() == "FALSE":
        return False

    num_match = re.match(
        r"^(amount|user.age)\s*(>=|<=|>|<|=|!=)\s*(\d+(?:\.\d+)?)$", dsl_expression
    )
    if num_match:
        f_name, op, val = num_match.groups()
        rule_val = Decimal(val)

        if f_name == "amount":
            tx_val = transaction.amount
        else:
            tx_val = user.age
            if tx_val is None:
                return False
            tx_val = Decimal(tx_val)
        if op == ">":
            return tx_val > rule_val
        if op == ">=":
            return tx_val >= rule_val
        if op == "<":
            return tx_val < rule_val
        if op == "<=":
            return tx_val <= rule_val
        if op == "=":
            return tx_val == rule_val
        if op == "!=":
            return tx_val != rule_val

    str_match = re.match(
        r"^(currency|merchantId|ipAddress|deviceId|user.region|user.name)\s*(=|!=)\s*'([^']*)'$",
        dsl_expression,
    )
    if str_match:
        f_name, op, rule_val = str_match.groups()
        if f_name.startswith("user."):
            attr_name = f_name.split(".")[1]
            tx_val = getattr(user, attr_name, None)
            if tx_val is None:
                return False
        else:
            field_map = {
                "currency": "currency",
                "merchantId": "merchant_id",
                "ipAddress": "ip_address",
                "deviceId": "device_id",
            }
            tx_val = getattr(transaction, field_map.get(f_name, ""), None)
        tx_val_str = str(tx_val)
        if op == "=":
            return tx_val_str == rule_val
        if op == "!=":
            return tx_val_str != rule_val
    return False
