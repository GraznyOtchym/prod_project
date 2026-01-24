from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db import get_session
from dependencies import get_current_user, is_admin
from models import FraudRule, Transaction, User
from schemas import (
    MerchantRiskRow,
    MerchantRiskStats,
    Role,
    RuleMatchRow,
    RuleMatchStats,
    StatsOverview,
    TransactionsTimePoint,
    TransactionsTimeSeries,
    UserRiskProfile,
)

router = APIRouter(prefix="/api/v1/stats", tags=["Statistics"])


def validate_period(date_from: datetime, date_to: datetime, max_days: int = 90):
    if date_from >= date_to:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_FAILED",
                "message": "'from' must be less than 'to'",
            },
        )
    if (date_to - date_from) > timedelta(days=max_days):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "VALIDATION_FAILED",
                "message": f"Period cannot exceed {max_days} days",
            },
        )


@router.get("/overview", response_model=StatsOverview)
async def get_overview(
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    if not date_to:
        date_to = now
    if not date_from:
        date_from = date_to - timedelta(days=30)

    validate_period(date_from, date_to)

    query = select(
        func.count(Transaction.id).label("volume"),
        func.coalesce(func.sum(Transaction.amount), 0).label("gmv"),
        func.count(Transaction.id)
        .filter(Transaction.extra_metadata["status"].astext == "APPROVED")
        .label("approved"),
        func.count(Transaction.id)
        .filter(Transaction.extra_metadata["status"].astext == "DECLINED")
        .label("declined"),
    ).where(Transaction.timestamp >= date_from, Transaction.timestamp < date_to)

    result = await session.execute(query)
    stats = result.one()

    volume = stats.volume
    gmv = float(stats.gmv)

    approval_rate = round(stats.approved / volume, 2) if volume > 0 else 0.0
    decline_rate = round(stats.declined / volume, 2) if volume > 0 else 0.0

    merchant_query = (
        select(
            Transaction.merchant_id,
            Transaction.merchant_category_code,
            func.count(Transaction.id).label("tx_count"),
            func.coalesce(func.sum(Transaction.amount), 0).label("gmv"),
            func.count(Transaction.id)
            .filter(Transaction.extra_metadata["status"].astext == "DECLINED")
            .label("declined_count"),
        )
        .where(
            Transaction.timestamp >= date_from,
            Transaction.timestamp < date_to,
            Transaction.merchant_id.is_not(None),
        )
        .group_by(Transaction.merchant_id, Transaction.merchant_category_code)
        .having(func.count(Transaction.id) > 0)
    )

    merchants_res = await session.execute(merchant_query)
    merchants_data = []

    for row in merchants_res.all():
        m_rate = (
            round(row.declined_count / row.tx_count, 2) if row.tx_count > 0 else 0.0
        )
        merchants_data.append(
            MerchantRiskRow(
                merchantId=row.merchant_id,
                merchantCategoryCode=row.merchant_category_code,
                txCount=row.tx_count,
                gmv=float(row.gmv),
                declineRate=m_rate,
            )
        )

    top_merchants = sorted(merchants_data, key=lambda x: x.declineRate, reverse=True)[
        :10
    ]

    return StatsOverview(
        from_=date_from,
        to=date_to,
        volume=volume,
        gmv=round(gmv, 2),
        approvalRate=approval_rate,
        declineRate=decline_rate,
        topRiskMerchants=top_merchants,
    )


@router.get("/transactions/timeseries", response_model=TransactionsTimeSeries)
async def get_timeseries(
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    group_by: str = Query("day", alias="groupBy", regex="^(hour|day|week)$"),
    channel: str | None = None,
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    if not date_to:
        date_to = now
    if not date_from:
        date_from = date_to - timedelta(days=7)

    max_days = 7 if group_by == "hour" else 90
    validate_period(date_from, date_to, max_days)

    trunc_col = func.date_trunc(group_by, Transaction.timestamp).label("bucket")

    query = select(
        trunc_col,
        func.count(Transaction.id).label("tx_count"),
        func.coalesce(func.sum(Transaction.amount), 0).label("gmv"),
        func.count(Transaction.id)
        .filter(Transaction.extra_metadata["status"].astext == "APPROVED")
        .label("approved"),
        func.count(Transaction.id)
        .filter(Transaction.extra_metadata["status"].astext == "DECLINED")
        .label("declined"),
    ).where(Transaction.timestamp >= date_from, Transaction.timestamp < date_to)

    if channel:
        query = query.where(Transaction.channel == channel)

    query = query.group_by(trunc_col).order_by(trunc_col)

    result = await session.execute(query)
    points = []

    for row in result.all():
        total = row.tx_count
        points.append(
            TransactionsTimePoint(
                bucketStart=row.bucket,
                txCount=total,
                gmv=float(row.gmv),
                approvalRate=round(row.approved / total, 2) if total > 0 else 0.0,
                declineRate=round(row.declined / total, 2) if total > 0 else 0.0,
            )
        )

    return TransactionsTimeSeries(points=points)


@router.get("/rules/matches", response_model=RuleMatchStats)
async def get_rules_matches(
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    top: int = Query(20, ge=1, le=100),
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    if not date_to:
        date_to = now
    if not date_from:
        date_from = date_to - timedelta(days=30)
    validate_period(date_from, date_to)

    query = select(
        Transaction.user_id,
        Transaction.merchant_id,
        Transaction.extra_metadata,
        Transaction.id,
    ).where(Transaction.timestamp >= date_from, Transaction.timestamp < date_to)
    result = await session.execute(query)
    txs = result.all()

    stats = {}
    total_declines = 0

    rules_res = await session.execute(select(FraudRule.id, FraudRule.name))
    rules_map = {str(r.id): r.name for r in rules_res.all()}

    for tx in txs:
        meta = tx.extra_metadata or {}
        is_fraud = meta.get("isFraud", False)
        if is_fraud:
            total_declines += 1

        rule_results = meta.get("ruleResults", [])
        for r_res in rule_results:
            if r_res.get("matched"):
                r_id = r_res.get("ruleId")
                if not r_id:
                    continue

                if r_id not in stats:
                    stats[r_id] = {"matches": 0, "users": set(), "merchants": set()}

                stats[r_id]["matches"] += 1
                if tx.user_id:
                    stats[r_id]["users"].add(tx.user_id)
                if tx.merchant_id:
                    stats[r_id]["merchants"].add(tx.merchant_id)

    # Формируем ответ
    items = []
    for r_id, data in stats.items():
        share = (
            round(data["matches"] / total_declines, 2) if total_declines > 0 else 0.0
        )
        items.append(
            RuleMatchRow(
                ruleId=r_id,
                ruleName=rules_map.get(r_id, "Unknown Rule"),
                matches=data["matches"],
                uniqueUsers=len(data["users"]),
                uniqueMerchants=len(data["merchants"]),
                shareOfDeclines=share,
            )
        )

    items.sort(key=lambda x: x.matches, reverse=True)
    return RuleMatchStats(items=items[:top])


@router.get("/merchants/risk", response_model=MerchantRiskStats)
async def get_merchant_risk(
    date_from: datetime | None = Query(None, alias="from"),
    date_to: datetime | None = Query(None, alias="to"),
    mcc: str | None = Query(None, alias="merchantCategoryCode", regex=r"^\d{4}$"),
    top: int = Query(50, ge=1, le=200),
    admin: User = Depends(is_admin),
    session: AsyncSession = Depends(get_session),
):
    now = datetime.now(timezone.utc)
    if not date_to:
        date_to = now
    if not date_from:
        date_from = date_to - timedelta(days=30)
    validate_period(date_from, date_to)

    query = select(
        Transaction.merchant_id,
        Transaction.merchant_category_code,
        func.count(Transaction.id).label("tx_count"),
        func.coalesce(func.sum(Transaction.amount), 0).label("gmv"),
        func.count(Transaction.id)
        .filter(Transaction.extra_metadata["status"].astext == "DECLINED")
        .label("declined"),
    ).where(
        Transaction.timestamp >= date_from,
        Transaction.timestamp < date_to,
        Transaction.merchant_id.is_not(None),
    )

    if mcc:
        query = query.where(Transaction.merchant_category_code == mcc)

    query = query.group_by(Transaction.merchant_id, Transaction.merchant_category_code)

    result = await session.execute(query)

    items = []
    for row in result.all():
        d_rate = round(row.declined / row.tx_count, 2) if row.tx_count > 0 else 0.0
        items.append(
            MerchantRiskRow(
                merchantId=row.merchant_id,
                merchantCategoryCode=row.merchant_category_code,
                txCount=row.tx_count,
                gmv=float(row.gmv),
                declineRate=d_rate,
            )
        )

    items.sort(key=lambda x: (x.declineRate, x.gmv), reverse=True)

    return MerchantRiskStats(items=items[:top])


@router.get("/users/{id}/risk-profile", response_model=UserRiskProfile)
async def get_user_risk_profile(
    id: str,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    target_uuid = uuid.UUID(id)
    if user.role != Role.ADMIN and user.id != target_uuid:
        raise HTTPException(status_code=403, detail="FORBIDDEN")

    target = await session.get(User, target_uuid)
    if not target:
        raise HTTPException(status_code=404, detail="USER_NOT_FOUND")

    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    month_ago = now - timedelta(days=30)

    q_24h = select(
        func.count(Transaction.id).label("cnt"),
        func.coalesce(func.sum(Transaction.amount), 0).label("gmv"),
        func.count(func.distinct(Transaction.device_id)).label("dist_dev"),
        func.count(func.distinct(Transaction.ip_address)).label("dist_ip"),
        func.count(func.distinct(Transaction.location["city"].astext)).label(
            "dist_city"
        ),
    ).where(Transaction.user_id == target_uuid, Transaction.timestamp >= day_ago)

    res_24h = (await session.execute(q_24h)).one()

    q_30d = select(
        func.count(Transaction.id).label("total"),
        func.count(Transaction.id)
        .filter(Transaction.extra_metadata["status"].astext == "DECLINED")
        .label("declined"),
    ).where(Transaction.user_id == target_uuid, Transaction.timestamp >= month_ago)
    res_30d = (await session.execute(q_30d)).one()

    d_rate = round(res_30d.declined / res_30d.total, 2) if res_30d.total > 0 else 0.0

    q_last = select(func.max(Transaction.timestamp)).where(
        Transaction.user_id == target_uuid
    )
    last_seen = await session.scalar(q_last)

    return UserRiskProfile(
        userId=str(target_uuid),
        txCount_24h=res_24h.cnt,
        gmv_24h=float(res_24h.gmv),
        distinctDevices_24h=res_24h.dist_dev,
        distinctIps_24h=res_24h.dist_ip,
        distinctCities_24h=res_24h.dist_city,
        declineRate_30d=d_rate,
        lastSeenAt=last_seen,
    )
