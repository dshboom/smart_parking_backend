from sqlalchemy import Column, Integer, Numeric, ForeignKey, Enum, String, Index
from sqlalchemy.sql import func
from auth.database import Base, UTCDateTime
from auth.core.enums import PaymentMethod, WalletTransactionType

class WalletAccount(Base):
    __tablename__ = "wallet_accounts"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    balance = Column(Numeric(12, 2), nullable=False, default=0)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    updated_at = Column(UTCDateTime, default=func.now(), onupdate=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_wallet_user", "user_id"),
    )

class WalletTransaction(Base):
    __tablename__ = "wallet_transactions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    amount = Column(Numeric(12, 2), nullable=False)
    transaction_type = Column(Enum(WalletTransactionType), nullable=False)
    method = Column(Enum(PaymentMethod), nullable=True)
    status = Column(String(20), nullable=False, default="SUCCESS")
    remark = Column(String(255), nullable=True)
    created_at = Column(UTCDateTime, default=func.now(), nullable=False)
    __table_args__ = (
        Index("idx_wallet_tx_user_type", "user_id", "transaction_type"),
    )