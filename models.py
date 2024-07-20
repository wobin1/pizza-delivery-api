from database import Base
from sqlalchemy import Column, Integer, String, Text, ForeignKey, Boolean
from sqlalchemy_utils.types import ChoiceType
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(Text, nullable=True)
    is_staff = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=False)
    orders = relationship('Order', back_populates='user')

    def __repr__(self):
        return f"<User {self.username}>"


class Order(Base):

    ORDER_STATUS = (
        ('PENDING', 'pending'),
        ('IN-TRANSIT', 'in-transit'),
        ('DELIVERED', 'deliver')
    )

    PIZZA_SIZES=(
        ('SMALL', 'small'),
        ('MEDIUM', 'medium'),
        ('LARGE', 'large'),
        ('EXTRA-LARGE', 'extra-large')
    )

    __tablename__='orders'
    id = Column(Integer, primary_key=True)
    quantity = Column(Integer, nullable=False)
    order_status = Column(ChoiceType(choices=ORDER_STATUS), default="PENDING")
    pizza_size=Column(ChoiceType(choices=PIZZA_SIZES), default="SMALL")
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship('User', back_populates='orders')

    def __repr__(self):
        return f"<Order {self.id}>"