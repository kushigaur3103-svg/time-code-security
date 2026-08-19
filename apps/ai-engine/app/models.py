from sqlalchemy import Column, String, DateTime
from datetime import datetime
import uuid
from .database import Base

class Scan(Base):
    __tablename__ = "Scan"

    id = Column(String, primary_key=True, index=True, default=lambda: "cuid_" + uuid.uuid4().hex[:10])
    fileName = Column(String, nullable=False)
    vulnerabilityType = Column(String, nullable=False)
    riskLevel = Column(String, nullable=False)
    status = Column(String, nullable=False)
    createdAt = Column(DateTime, default=datetime.utcnow)
