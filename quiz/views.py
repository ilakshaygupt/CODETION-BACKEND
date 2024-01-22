from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework_simplejwt.authentication import JWTAuthentication
from quiz.permissions import  AllowAny, IsQuizAdmin, IsQuizAdminOrReadOnly, IsRegisteredParticipant, MultipleFieldLookupMixin
from .models import Quiz, Question, Choice
from .serializers import QuestionCreateSerializer, QuestionDisplaySerializer, QuizCreateSerializer, QuizSerializer, ChoiceSerializer , QuizDisplaySerializer

class QuizViewSet(viewsets.ModelViewSet):
    queryset = Quiz.objects.all()
    serializer_class = QuizSerializer
    authentication_classes = [JWTAuthentication]
    lookup_field = 'id'
        
    def get_serializer_class(self):
        if self.request.method=='POST':
            return QuizCreateSerializer
        elif self.request.method == 'GET':
            return QuizDisplaySerializer
        return QuizSerializer

    def get_permissions(self):
        if self.request.method=='POST':
            return [AllowAny()]
        elif self.request.method == 'GET':
            return [AllowAny()]
        return [IsQuizAdmin()]

class QuestionCreateGet(viewsets.ModelViewSet):
    queryset = Question.objects.all()
    serializer_class = QuizSerializer
    authentication_classes = [JWTAuthentication]
    lookup_field = 'quiz_id'

    def get_queryset(self):
        quiz_id = self.kwargs.get('quiz_id')
        return Question.objects.filter(quiz_id=quiz_id)
    
    def get_serializer_class(self):
        if self.request.method=='POST':
            return QuestionCreateSerializer
        elif self.request.method == 'GET':
            return QuestionDisplaySerializer
        return QuestionDisplaySerializer
    
    def perform_create(self, serializer):
        serializer.save()

    def get_permissions(self):
        if self.request.method=='POST':
            return [IsQuizAdminOrReadOnly()]
        elif self.request.method == 'GET':
            return [AllowAny()]
        return [IsQuizAdminOrReadOnly()]

class QuestionViewSet(MultipleFieldLookupMixin,viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    lookup_fields = ('id', 'quiz_id')
    def get_queryset(self,):
        quiz_id = self.kwargs.get('quiz_id')
        id = self.kwargs.get('id')
        return Question.objects.filter(quiz_id=quiz_id, id=id)
        
    def get_permissions(self):
        if self.request.method=='POST':
            return [IsQuizAdmin()]
        elif self.request.method == 'GET':
            return [IsRegisteredParticipant()]
        return [IsQuizAdmin()]
    
    def get_serializer_class(self):
        if self.request.method=='POST':
            return QuestionCreateSerializer
        elif self.request.method == 'GET':
            return QuestionDisplaySerializer
        return QuestionDisplaySerializer
