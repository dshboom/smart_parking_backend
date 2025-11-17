from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List
from datetime import datetime
from decimal import Decimal
from auth.core.enums import PaymentMethod, WalletTransactionType

class WalletBalanceRead(BaseModel):
    balance: Decimal

class WalletRechargeRequest(BaseModel):
    amount: Decimal = Field(..., gt=0)
    payment_method: PaymentMethod

class WalletWithdrawRequest(BaseModel):
    amount: Decimal = Field(..., gt=0)
    bank_account: Optional[str] = None

class WalletTransactionRead(BaseModel):
    id: int
    user_id: int
    amount: Decimal
    transaction_type: WalletTransactionType
    method: Optional[PaymentMethod] = None
    status: str
    remark: Optional[str] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class WalletTransactionList(BaseModel):
    total: int
    transactions: List[WalletTransactionRead]

class WalletMethodRead(BaseModel):
    method: PaymentMethod
    name: str
    provider: Optional[str] = None