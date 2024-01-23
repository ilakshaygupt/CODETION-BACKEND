from django.urls import path
from . import views

urlpatterns = [
    path('', views.QuizViewSet.as_view({'post': 'create','get': 'list'}), name='quiz-list'),
    path('<int:id>/', views.QuizViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='quiz-detail'),
    path('<int:quiz_id>/question/', views.QuestionCreateGet.as_view({'post': 'create','get': 'list'}), name='question-list'),
    path('question/<int:id>/', views.QuestionViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='question-detail'),
    path('question/<int:question_id>/submission/<int:id>/', views.SubmissionCreateGet.as_view({'post': 'create','get': 'list','get':'retrieve'}), name='choice-list'),
    path('score/', views.ScoreViewSet.as_view(), name='score-list'),

]
