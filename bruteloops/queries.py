from . import sql
from sqlalchemy import (
    select, delete, join,
    update, not_)

# ================
# USERNAME QUERIES
# ================

# Where clauses applicable to to all Username queries.
COMMON_USERNAME_WHERE_CLAUSES = CWC = (
    sql.Username.recovered    == False,
    sql.Username.actionable   == True,)

HAS_UNGUESSED_SUBQUERY = (
    select(sql.Credential.id)
        .where(
            sql.Username.id == sql.Credential.username_id,
            sql.Credential.guess_time == -1,
            sql.Credential.guessed == False)
        .limit(1)
).exists()

strict_usernames = (
    select(sql.Username.id)
        .where(
            *CWC,
            sql.Username.priority == False,
            HAS_UNGUESSED_SUBQUERY,
            (
                select(sql.StrictCredential)
                    .join(
                        sql.Credential,
                        sql.StrictCredential.credential_id ==
                            sql.Credential.id)
                    .where(
                        sql.Credential.username_id ==
                            sql.Username.id)
                    .limit(1)
            ).exists()
        )
        .distinct()
)

priority_usernames = (
    select(sql.Username.id)
        .where(
            *CWC,
            sql.Username.priority == True,
            HAS_UNGUESSED_SUBQUERY)
        .distinct()
)

usernames = (
    select(sql.Username.id)
        .where(
            *CWC,
            HAS_UNGUESSED_SUBQUERY)
        .distinct()
)

# ==================
# CREDENTIAL QUERIES
# ==================

COMMON_CREDENTIAL_WHERE_CLAUSES = CCWC = (
    sql.Credential.guess_time == -1,
    sql.Credential.guessed == False,
)

strict_credentials = (
    select(sql.StrictCredential)
        .join(
            sql.Credential,
            sql.StrictCredential.credential_id == sql.Credential.id)
        .where(*CCWC)
)

priority_credentials = (
    select(sql.PriorityCredential)
        .join(
            sql.Credential,
            sql.PriorityCredential.credential_id == sql.Credential.id)
        .join(
            sql.Password,
            sql.Credential.password_id == sql.Password.id)
        .where(
            *CCWC,
            sql.Password.priority == True)
)

credentials = (
    select(sql.Credential.id)
        .join(
            sql.Username,
            sql.Credential.username_id == sql.Username.id)
        .join(
            sql.Password,
            sql.Credential.password_id == sql.Password.id)
        .where(*CCWC)
)


