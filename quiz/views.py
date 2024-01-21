from rest_framework import viewsets
from rest_framework.response import Response
from .models import Quiz, Question, Choice
from .serializers import QuizSerializer, QuestionSerializer, ChoiceSerializer

class QuizViewSet(viewsets.ModelViewSet):
    queryset = Quiz.objects.all()
    serializer_class = QuizSerializer

class QuestionViewSet(viewsets.ModelViewSet):
    queryset = Question.objects.all()
    serializer_class = QuestionSerializer

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        response = serializer.data
        choices = Choice.objects.filter(question=instance)
        response['choices'] = ChoiceSerializer(choices, many=True).data
        return Response(response)