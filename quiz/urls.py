from django.urls import path
from . import views

urlpatterns = [
    path('quiz/', views.QuizViewSet.as_view({'get': 'list', 'post': 'create'}), name='quiz-list'),
    path('quiz/<int:pk>/', views.QuizViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='quiz-detail'),
    path('question/', views.QuestionViewSet.as_view({'get': 'list', 'post': 'create'}), name='question-list'),
    path('question/<int:pk>/', views.QuestionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='question-detail'),
]
