from django.urls import path
from . import views

urlpatterns = [
    path('quiz/', views.QuizViewSet.as_view({'post': 'create','get': 'list'}), name='quiz-list'),
    path('quiz/<int:id>/', views.QuizViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='quiz-detail'),
    path('quiz/<int:quiz_id>/question/', views.QuestionCreateGet.as_view({'post': 'create','get': 'list'}), name='question-list'),
    path('quiz/<int:quiz_id>/question/<int:id>/', views.QuestionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='question-detail'),
]
