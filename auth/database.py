import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import sqlalchemy.types as types
from dotenv import load_dotenv
from datetime import datetime, timezone

class UTCDateTime(types.TypeDecorator):
    impl = types.DateTime
    cache_ok = True
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc)
        return value
    
    def process_result_value(self, value, dialect):
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

load_dotenv()
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL 环境变量未设置，请在 .env 文件中配置")
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=3600,
    echo=False,  # 可查看SQL语句，调试用
    connect_args={"charset": "utf8mb4", "init_command": "SET time_zone = '+00:00'"}  # 设置MySQL时区为UTC
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
Base = declarative_base()
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        print("数据库表创建成功")
    except Exception as e:
        print(f"数据库初始化失败: {e}")
        raise

def test_connection():
    try:
        db = SessionLocal()
        db.execute("SELECT 1")
        db.close()
        print("数据库连接成功")
        return True
    except Exception as e:
        print(f"数据库连接失败: {e}")
        return False