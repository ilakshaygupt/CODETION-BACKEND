from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from quiz.permissions import  AllowAny, IsQuizAdmin, IsQuizAdminOrReadOnly, MultipleFieldLookupMixin
from .models import Quiz, Question, Choice, Submission
from .serializers import QuestionCreateSerializer, QuestionDisplaySerializer, QuestionUpdateSerializer, QuizCreateSerializer, QuizSerializer, ChoiceSerializer , QuizDisplaySerializer, SubmissionCreateSerializer

#For creating  and listing  as well as updating ,finding a particular quiz and deleting a quiz
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


# For creating a question and listing all quesiton qith help of quiz id
class QuestionCreateGet(viewsets.ModelViewSet):
    queryset = Question.objects.all()
    serializer_class = QuizSerializer
    authentication_classes = [JWTAuthentication]
    lookup_field = 'quiz_id'

    def get_queryset(self):
        quiz_id = self.kwargs.get('quiz_id')
        return Question.objects.filter(quiz_id=quiz_id)
    
    def get_serializer_class(self):
        if self.request.method=='POST' :
            return QuestionCreateSerializer
        elif self.request.method == 'GET':
            return QuestionDisplaySerializer
        return QuestionDisplaySerializer
    
    def perform_create(self, serializer):
        serializer.save()

    def get_permissions(self):
        if self.request.method=='POST':
            return [IsQuizAdmin()]
        elif self.request.method == 'GET':
            return [IsQuizAdminOrReadOnly()]
        return [IsQuizAdmin()]


# For getting a particular question and updating and deleting a question
class QuestionViewSet(MultipleFieldLookupMixin,viewsets.ModelViewSet):
    authentication_classes = [JWTAuthentication]
    lookup_fields = ('id')
    def get_queryset(self,):
        id = self.kwargs.get('id')
        return Question.objects.filter( id=id)
    
    def get_permissions(self):
        if self.request.method=='POST' :
            return [IsQuizAdmin()]
        elif self.request.method == 'GET':
            return [IsQuizAdminOrReadOnly()]
        return [IsQuizAdmin()]
    
    def get_serializer_class(self):
        if  self.request.method=='PATCH':
            return QuestionUpdateSerializer
        elif self.request.method == 'GET':
            return QuestionDisplaySerializer
        return QuestionDisplaySerializer

class SubmissionCreateGet(viewsets.ModelViewSet):
    queryset = Submission.objects.all()
    serializer_class = QuizSerializer
    authentication_classes = [JWTAuthentication]
    lookup_field = 'id'

    def get_queryset(self):
        choice_id = self.kwargs.get('id')
        user = self.request.user
        return Submission.objects.filter(selected_choice_id=choice_id,quizinee=user)
    
    def get_serializer_class(self):
        if self.request.method=='POST' :
            return SubmissionCreateSerializer
    def perform_create(self, serializer):
        serializer.save()
  
    def get_permissions(self):
        if self.request.method=='POST':
            return [AllowAny()]
        elif self.request.method == 'GET':
            return [IsQuizAdminOrReadOnly()]
        return [IsQuizAdmin()]