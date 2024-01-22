import datetime
from django.db import models
from authentication.models import User
from django.utils import timezone

class Quiz(models.Model):
    admin = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=200,unique=True)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    description = models.TextField(max_length=500, blank=True)

    def getTotalQuestion(self):
        question = len(Question.objects.filter(quiz_id=self.id))
        return question
    def getTotalParticipant(self):
        participant = len(RegisteredParticipant.objects.filter(quiz_id=self.id))
        return participant
    def isStarted(self):
        return self.start_time <= timezone.now()
    
    def isEnded(self):
        return self.end_time <= timezone.now()
    
    def isOngoing(self):
        return self.isStarted() and not self.isEnded()
    
    def __str__(self):
        return str(self.id) + "." + str(self.title)


class RegisteredParticipant(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    quizinee = models.ForeignKey(User, on_delete=models.CASCADE)

class Question(models.Model):
    title = models.CharField(max_length=200)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    description = models.TextField(max_length=500, blank=True)
    def getCorrectChoice(self):
        return Choice.objects.filter(question=self.id, is_correct=True)
    
    def getTotalChoices(self):
        return len(Choice.objects.filter(question=self.id))
    def is_correct_option(self):
        return len(Choice.objects.filter(question=self.id, is_correct=True)) == 1
    
    def __str__(self):
        return str(self.id) + " " + self.quiz.title

class Choice(models.Model):
    choice_text = models.CharField(max_length=200)
    is_correct = models.BooleanField(default=False)
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='choices')
    
    def __str__(self):
        return str(self.id) + " -->  " +  str(self.choice_text) 


class Submission(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE,null=True, blank=True)
    quizinee = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    selected_choice = models.ForeignKey(Choice, on_delete=models.CASCADE, null=True, blank=True)

    def isCorrect(self):
        return self.selected_choice.is_correct
    def alreadySubmitted(self):
        return len(Submission.objects.filter(quiz=self.quiz, quizinee=self.quizinee)) >= 1
    def __str__(self):
        return "BY---->"+str(self.quizinee.username) + "|    QUESTION----->   "+ str(self.question.title) + " |   SELECTED OPTION---->  "+str(self.selected_choice.choice_text)
    