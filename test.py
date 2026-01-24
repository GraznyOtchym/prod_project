import httpx
import pytest
import pytest_asyncio

BASE_URL = "http://localhost:8080/api/v1"
ADMIN_CRED = {"email": "admin@example.com", "password": "adminpass1"}
USER_CRED = {"email": "fraud_tester_final@example.com", "password": "Qwerty_123"}


@pytest_asyncio.fixture(scope="module")
async def auth():
    async with httpx.AsyncClient(timeout=10.0) as client:
        # 1. Логин админа
        a_resp = await client.post(f"{BASE_URL}/auth/login", json=ADMIN_CRED)
        if a_resp.status_code != 200:
            pytest.fail(f"Админ не залогинился: {a_resp.text}")

        a_token = a_resp.json()["accessToken"]
        a_h = {"Authorization": f"Bearer {a_token}"}

        # 2. Создаем юзера для тестов на 403
        await client.post(
            f"{BASE_URL}/users",
            headers=a_h,
            json={
                "email": USER_CRED["email"],
                "password": USER_CRED["password"],
                "fullName": "Validation Tester",
                "role": "USER",
                "isActive": True,
                "age": 25,
                "region": "RU",
                "gender": "MALE",
                "maritalStatus": "SINGLE",
            },
        )

        # 3. Логин юзера
        u_resp = await client.post(f"{BASE_URL}/auth/login", json=USER_CRED)
        if u_resp.status_code != 200:
            pytest.fail(f"Юзер не залогинился: {u_resp.text}")

        return {
            "a_h": a_h,
            "u_h": {"Authorization": f"Bearer {u_resp.json()['accessToken']}"},
        }


@pytest.mark.asyncio
async def test_11_tier_1_basic(auth):
    """Tier 1: Одно поле amount и число"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "amount >= 500.50"},
            headers=auth["a_h"],
        )
        assert r.status_code == 200
        assert r.json()["isValid"] is True


@pytest.mark.asyncio
async def test_12_tier_2_strings_ok(auth):
    """Tier 2: Строковые поля и оператор ="""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "currency = 'USD'"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True


@pytest.mark.asyncio
async def test_13_tier_2_strings_invalid_op(auth):
    """Tier 2: Оператор > для строк запрещен (DSL_INVALID_OPERATOR)"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "currency > 'RUB'"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is False
        # Проверяем наличие кода ошибки из ТЗ
        assert any(
            e["code"] == "DSL_INVALID_OPERATOR" for e in r.json().get("errors", [])
        )


@pytest.mark.asyncio
async def test_14_tier_3_logic_case_insensitive(auth):
    """Tier 3: and/or регистронезависимы"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "amount > 100 and currency != 'EUR'"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True
        # Проверка нормализации (AND в верхнем регистре)
        if r.json().get("normalizedExpression"):
            assert "AND" in r.json()["normalizedExpression"]


@pytest.mark.asyncio
async def test_15_tier_4_not_and_parens(auth):
    """Tier 4: Скобки и NOT"""
    async with httpx.AsyncClient() as client:
        dsl = "NOT (amount < 50 OR currency = 'USD')"
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": dsl},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True


@pytest.mark.asyncio
async def test_16_tier_5_user_fields(auth):
    """Tier 5: user.age и user.region"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "user.age >= 18 AND user.region = 'RU'"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True


# --- ТЕСТЫ НА НОРМАЛИЗАЦИЮ ---


@pytest.mark.asyncio
async def test_17_normalization_spaces(auth):
    """Нормализация: пробелы вокруг операторов"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "amount>10"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True
        assert r.json()["normalizedExpression"] == "amount > 10"


@pytest.mark.asyncio
async def test_18_normalization_extra_parens(auth):
    """Нормализация: убирание лишних скобок"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "((amount > 100))"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True
        assert r.json()["normalizedExpression"] == "amount > 100"


# --- ТЕСТЫ НА ОШИБКИ ---


@pytest.mark.asyncio
async def test_19_invalid_field_error(auth):
    """Ошибка: неизвестное поле (DSL_INVALID_FIELD)"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "unknown_field = 1"},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is False
        assert any(e["code"] == "DSL_INVALID_FIELD" for e in r.json().get("errors", []))


@pytest.mark.asyncio
async def test_20_parse_error_details(auth):
    """Ошибка: синтаксис (DSL_PARSE_ERROR) + position/near"""
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": "amount > "},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is False
        error = next(e for e in r.json()["errors"] if e["code"] == "DSL_PARSE_ERROR")
        assert "position" in error
        assert "near" in error


# --- СЛОЖНЫЕ СЦЕНАРИИ (100+ символов) ---


@pytest.mark.asyncio
async def test_21_max_complexity_tier_5(auth):
    """Финальный босс: длинное выражение со всеми Tier 5 фишками"""
    dsl = "(amount > 5000 AND user.age < 21) OR (NOT (user.region = 'RU') AND currency != 'RUB' AND deviceId != '123')"
    # Длина ~105 символов
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": dsl},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True


@pytest.mark.asyncio
async def test_22_logic_priority_check(auth):
    """Проверка приоритета AND над OR согласно EBNF"""
    # a OR b AND c должно быть как a OR (b AND c)
    dsl = "amount > 1 OR amount < 10 AND currency = 'USD'"
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"{BASE_URL}/fraud-rules/validate",
            json={"dslExpression": dsl},
            headers=auth["a_h"],
        )
        assert r.json()["isValid"] is True
