from fastapi import APIRouter, status, Depends
from auth_routes import get_current_user


order_router = APIRouter(
    prefix='/orders',
    tags=['Orders']  # tag for grouping the routes under the "Orders" tag in Swagger UI
)


@order_router.get('/')
def order_app(current_user:dict = Depends(get_current_user)):
    return {'message': 'order route working perfectly fine'}