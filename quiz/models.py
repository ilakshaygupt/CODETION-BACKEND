import datetime
from django.db import models
from authentication.models import User

class Quiz(models.Model):
    admin = models.ForeignKey(User, on_delete=models.CASCADE)
    unique_code = models.IntegerField(unique=True)
    title = models.CharField(max_length=200)
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    description = models.TextField(max_length=500, blank=True)

    def getTotalQuestion(self):
        question = len(Question.objects.filter(quiz_id=self.id))
        return question
    def getTotalParticipant(self):
        participant = len(RegisteredParticipant.objects.filter(quiz_id=self.id))
        return participant
    
    def getParticipant(self):
        participant = RegisteredParticipant.objects.filter(quiz_id=self.id)
        return participant
    
    def isStarted(self):
        return self.start_time <= datetime.datetime.now()
    
    def isEnded(self):
        return self.end_time <= datetime.datetime.now()
    
    def isOngoing(self):
        return self.isStarted() and not self.isEnded()
    
    def __str__(self):
        return str(self.id) + "." + str(self.title)


class RegisteredParticipant(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    quizinee = models.ForeignKey(User, on_delete=models.CASCADE)

class Question(models.Model):
    title = models.CharField(max_length=200)
    unique_code = models.IntegerField(unique=True)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    description = models.TextField(max_length=500, blank=True)
    def getCorrectChoice(self):
        return Choice.objects.filter(question=self.id, is_correct=True)
    
    def getTotalChoices(self):
        return len(Choice.objects.filter(question=self.id))
    
    def __str__(self):
        return str(self.id) + " " + self.quiz.title

class Choice(models.Model):
    choice_text = models.CharField(max_length=200)
    is_correct = models.BooleanField(default=False)
    question = models.ForeignKey(Question, on_delete=models.CASCADE)
    
    def have_all_options(self):
        return len(Choice.objects.filter(question=self.question)) >= 4
    
    def have_correct_option(self):
        return len(Choice.objects.filter(question=self.question, is_correct=True)) >= 1
    
    def __str__(self):
        return str(self.id) + "." + str(self.choice_text + "(" + self.question.description + ")")


class Submission(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    quizinee = models.ForeignKey(User, on_delete=models.CASCADE)
    selected_choice = models.ForeignKey(Choice, on_delete=models.CASCADE)

    def isCorrect(self):
        return self.selected_choice.is_correct
    def alreadySubmitted(self):
        return len(Submission.objects.filter(quiz=self.quiz, quizinee=self.quizinee)) >= 1
    def __str__(self):
        return str(self.id) + "." + str(self.quizinee.username) + "(" + str(self.quiz.title) + ")"