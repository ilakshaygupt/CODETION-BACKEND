from django.urls import path
from . import views

urlpatterns = [
    path('quiz/', views.QuizViewSet.as_view({'post': 'create','get': 'list'}), name='quiz-list'),
    path('quiz/<int:id>/', views.QuizViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='quiz-detail'),
    path('quiz/<int:quiz_id>/question/', views.QuestionCreateGet.as_view({'post': 'create','get': 'list'}), name='question-list'),
    path('quiz/question/<int:id>/', views.QuestionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='question-detail'),
    path('quiz/question/<int:id>/Submission/', views.SubmissionCreateGet.as_view({'post': 'create','get': 'list','get':'retrieve'}), name='choice-list'),
]
