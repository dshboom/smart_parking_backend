import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# 导入你的 FastAPI 应用实例和数据库模型基类
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from main import app
    from auth.database import Base, get_db
except ImportError:
    # 如果相对导入失败，尝试绝对导入
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from main import app
    from auth.database import Base, get_db

# --- 测试数据库设置 ---
# 使用内存中的 SQLite 数据库进行测试
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}, # SQLite 需要这个参数
    poolclass=StaticPool, # 使用静态连接池
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# --- Pytest Fixtures ---
@pytest.fixture(scope="function")
def db_session():
    """
    为每个测试函数创建一个新的数据库会话和干净的表。
    """
    # 在测试开始前创建所有表
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        # 在测试结束后删除所有表，确保测试隔离
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    """
    创建一个 TestClient，并覆盖 get_db 依赖以使用测试数据库会话。
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            db_session.close()

    # 依赖覆盖：将应用中的 get_db 替换为我们的测试数据库会话
    app.dependency_overrides[get_db] = override_get_db
    
    yield TestClient(app)
    
    # 清理依赖覆盖
    app.dependency_overrides.clear()