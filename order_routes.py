from fastapi import APIRouter, status, Depends
from auth_routes import get_current_user
from schemas import ResponseModel, OrderModel


order_router = APIRouter(
    prefix='/orders',
    tags=['Orders']  # tag for grouping the routes under the "Orders" tag in Swagger UI
)


@order_router.get('/', response_model=ResponseModel)
def order_app(current_user:dict = Depends(get_current_user)):
    return {'status': True, 'message': f'Order route working perfectly fine', 'data': {"current_user": current_user}}


@order_router.post('/orders', response_model=ResponseModel)
def create_order(order=OrderModel, current_user:dict= Depends(get_current_user)):

    return {"status": True, 'message': 'Order created successfully', 'data': order}