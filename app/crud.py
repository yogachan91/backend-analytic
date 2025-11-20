from sqlalchemy.orm import Session
from sqlalchemy import text
from . import models, schemas, utils
from datetime import datetime, timedelta
from .utils import add_years_to_datetime
from .auth import create_refresh_token
import uuid

def get_user_by_email(db: Session, email: str):
    return db.query(models.User).filter(models.User.email == email).first()

def get_user(db: Session, user_id):
    return db.query(models.User).filter(models.User.id == user_id).first()

def create_user(db: Session, user_in: schemas.UserCreate):
    hashed = utils.hash_password(user_in.password)
    now = datetime.utcnow()
    expired = add_years_to_datetime(now, 1)
    user = models.User(
        nama=user_in.nama,
        email=user_in.email,
        pass_hash=hashed,
        tipe=user_in.tipe,
        created_date=now,
        expired_date=expired
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

def create_refresh_token_in_db(db: Session, user_id, token_str, expires_at):
    rt = models.RefreshToken(user_id=user_id, token=token_str, expires_at=expires_at)
    db.add(rt)
    db.commit()
    db.refresh(rt)
    return rt

def revoke_refresh_token(db: Session, token_str: str):
    rt = db.query(models.RefreshToken).filter(models.RefreshToken.token == token_str).first()
    if rt:
        db.delete(rt)
        db.commit()
    return True

def revoke_all_refresh_tokens_for_user(db: Session, user_id):
    db.query(models.RefreshToken).filter(models.RefreshToken.user_id == user_id).delete()
    db.commit()
    return True

def get_top_5_summary(db: Session):
    sql = text("""
WITH base AS (
  SELECT
    created_date,
    modul,
    LOWER(event_severity_label) AS severity,
    LOWER(sub_type) AS sub_type,
    rule_name,
    CASE
      WHEN SPLIT_PART(source_ip, '/', 1) LIKE '192.168.%'
        THEN SPLIT_PART(source_ip, '/', 1)
      WHEN SPLIT_PART(destination_ip, '/', 1) LIKE '192.168.%'
        THEN SPLIT_PART(destination_ip, '/', 1)
      ELSE NULL
    END AS internal_ip
  FROM countip
  WHERE
    SPLIT_PART(source_ip, '/', 1) LIKE '192.168.%'
    OR SPLIT_PART(destination_ip, '/', 1) LIKE '192.168.%'
),

rule_counts AS (
  SELECT internal_ip, rule_name, COUNT(*) AS rule_cnt
  FROM base
  WHERE internal_ip IS NOT NULL
  GROUP BY internal_ip, rule_name
),

scored AS (
  SELECT
    b.*,

    CASE b.modul
      WHEN 'suricata' THEN 1.0
      WHEN 'panw' THEN 1.2
      WHEN 'sophos' THEN 1.3
      ELSE 1.0
    END AS w_modul,

    CASE
      WHEN b.severity IN ('critical','severe') THEN 5.0
      WHEN b.severity = 'high' THEN 3.5
      WHEN b.severity = 'medium' THEN 2.0
      WHEN b.severity = 'low' THEN 1.0
      ELSE 0.5
    END AS w_severity,

    CASE
      WHEN b.sub_type IN ('malware','c2','command_and_control','data_exfil','exfiltration') THEN 5.5
      WHEN b.sub_type IN ('exploit_attempt','exploit','intrusion','lateral_movement') THEN 4.5
      WHEN b.sub_type IN ('auth_bruteforce','password_spray','credential_access') THEN 3.8
      WHEN b.sub_type IN ('policy_violation','misconfiguration') THEN 1.8
      ELSE 1.0
    END AS w_sub_type,

    CASE
      WHEN b.rule_name ILIKE '%mimikatz%' 
        OR b.rule_name ILIKE '%c2%' 
        OR b.rule_name ILIKE '%ransomware%' THEN 1.4
      WHEN b.rule_name ILIKE '%port scan%' 
        OR b.rule_name ILIKE '%generic%' THEN 0.8
      ELSE 1.0
    END AS w_rule,

    EXP(-1) AS time_decay,
    1.0 / (1.0 + LN(GREATEST(rc.rule_cnt, 1))) AS dup_damp

  FROM base b
  LEFT JOIN rule_counts rc
    ON rc.internal_ip = b.internal_ip AND rc.rule_name = b.rule_name
  WHERE b.internal_ip IS NOT NULL
),

per_event AS (
  SELECT
    internal_ip,
    modul,
    sub_type,
    (w_modul * w_severity * w_sub_type * w_rule * time_decay * dup_damp) AS event_score
  FROM scored
),

ip_agg AS (
  SELECT
    internal_ip,
    SUM(event_score) AS raw_score,
    COUNT(*) AS event_count,
    COUNT(DISTINCT modul) AS modul_count,
    COUNT(DISTINCT sub_type) AS sub_type_count
  FROM per_event
  GROUP BY internal_ip
),

final_raw AS (
  SELECT
    internal_ip,
    event_count,
    modul_count,
    sub_type_count,
    raw_score
      * (1 + 0.2 * (modul_count - 1))
      * (1 + 0.1 * LEAST(sub_type_count - 1, 3))
      AS score_raw
  FROM ip_agg
),

final AS (
  SELECT
    internal_ip,
    event_count,
    modul_count,
    sub_type_count,
    LEAST(100, GREATEST(1, score_raw * 2)) AS score_normalized
  FROM final_raw
)

SELECT
  internal_ip AS ip,
  event_count,
  modul_count,
  sub_type_count,
  ROUND(score_normalized::numeric, 2) AS score,
  CASE
    WHEN score_normalized >= 80 THEN 'Critical'
    WHEN score_normalized >= 60 THEN 'High'
    WHEN score_normalized >= 30 THEN 'Medium'
    ELSE 'Low'
  END AS severity
FROM final
ORDER BY score DESC
LIMIT 5;
    """)

    result = db.execute(sql)
    rows = result.fetchall()

    return [
        {
            "ip": r.ip,
            "event_count": r.event_count,
            "modul_count": r.modul_count,
            "sub_type_count": r.sub_type_count,
            "score": float(r.score),
            "severity": r.severity
        }
        for r in rows
    ]
