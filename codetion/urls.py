
from django.contrib import admin
from django.urls import path, include
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
schema_view = get_schema_view(
    info=openapi.Info(
        title="Test API",
        default_version="v1",
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@example.com"),
<<<<<<< HEAD
        license=openapi.License(name="MIT License"),
    ),
=======
        license=openapi.License(name="BSD License"),
    ),
    validators=["ssv", "flex"],
    public=True,
>>>>>>> origin/quiz
)
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("authentication.urls")),
    path("quizies/", include("quiz.urls")),
    path('swagger/', schema_view.with_ui('swagger',
         cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
         cache_timeout=0), name='schema-redoc'),
    path("__debug__/", include("debug_toolbar.urls")),

]
