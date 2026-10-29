from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView


class RefundView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        order = Order.objects.get(pk=request.data["order_id"])
        order.refund()
        return Response({"ok": True})
