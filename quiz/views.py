from rest_framework import viewsets
from rest_framework_simplejwt.authentication import JWTAuthentication
from authentication.renderers import UserRenderer
from quiz.permissions import  AllowAny, CanChangeQuestion, IsQuizAdmin, IsQuizAdminOrReadOnly, MultipleFieldLookupMixin
from .models import Quiz, Question, Choice, RegisteredParticipant, Submission
from .serializers import QuestionCreateSerializer, QuestionDisplaySerializer, QuestionUpdateSerializer, QuizCreateSerializer, QuizSerializer, ChoiceSerializer , QuizDisplaySerializer, SubmissionCreateSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
#For creating  and listing  as well as updating ,finding a particular quiz and deleting a quiz

class QuizViewSet(viewsets.ModelViewSet):
    renderer_classes = [UserRenderer]
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
    renderer_classes = [UserRenderer]
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
            return [CanChangeQuestion()]
        elif self.request.method == 'GET':
            return [IsQuizAdminOrReadOnly()]
        return [CanChangeQuestion()]


# For getting a particular question and updating and deleting a question
class QuestionViewSet(MultipleFieldLookupMixin,viewsets.ModelViewSet):
    renderer_classes = [UserRenderer]
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

class SubmissionCreateGet(MultipleFieldLookupMixin,viewsets.ModelViewSet):
    renderer_classes = [UserRenderer]
    queryset = Submission.objects.all()
    serializer_class = QuizSerializer
    authentication_classes = [JWTAuthentication]
    lookup_fields = ('id','question_id')

    def get_queryset(self):
        return Submission.objects.filter(selected_choice_id=self.kwargs.get('id'),
                                        quizinee=self.request.user,
                                        question_id=self.kwargs.get('question_id'))
    
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
    
class ScoreViewSet(APIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [IsQuizAdmin]
    def get(self, request, format=None):
        participants = RegisteredParticipant.objects.all().select_related('quizinee', 'quiz')
        for participant in participants:
            submissions = Submission.objects.filter(quizinee=participant.quizinee, question__quiz=participant.quiz, selected_choice__is_correct=True)
            score = 0
            for submission in submissions:
                if submission.selected_choice.is_correct:
                    score += 1
            participant.score = score
            participant.save()
        return Response({'Scores updated.':'adadad'}, status=status.HTTP_200_OK)
    