from rest_framework import serializers
from .models import Quiz, Question, Choice, Submission

class QuizSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = '__all__'

class QuizDisplaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ['id', 'title', 'start_time', 'end_time', 'description', 'getTotalQuestion', 'getTotalParticipant', 'isStarted', 'isEnded', 'isOngoing']


class QuizCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = ['title', 'start_time', 'end_time', 'description']
    def create(self, validated_data):
        quiz = Quiz.objects.create(**validated_data, admin=self.context['request'].user)
        return quiz
        
    
class ChoiceSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField()
    
    class Meta:
        model = Choice
        fields = ['id', 'choice_text', 'is_correct']
    
        
class ChoiceDisplaySerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['id', 'choice_text']
class ChoiceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['choice_text', 'is_correct']

class QuestionCreateSerializer(serializers.ModelSerializer):
    choices = ChoiceCreateSerializer(many=True)

    class Meta:
        model = Question
        fields = ['title', 'description', 'choices']

    def validate_choices(self, value):
        if len(value) != 4:
            raise serializers.ValidationError("Exactly four choices are required.")
        return value
    
    def create(self, validated_data):
        choices_data = validated_data.pop('choices')
        quiz_id = self.context['view'].kwargs['quiz_id']
        question = Question.objects.create(quiz_id=quiz_id, **validated_data)

        for choice_data in choices_data:
            Choice.objects.create(question=question, **choice_data)
        return question

class QuestionDisplaySerializer(serializers.ModelSerializer):
    choices = ChoiceDisplaySerializer(many=True)

    class Meta:
        model = Question
        fields = ['id', 'title', 'quiz', 'description', 'choices']

class QuestionUpdateSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True)

    class Meta:
        model = Question
        fields = ['id', 'title', 'quiz', 'description', 'choices']


    def validate_choices(self, value):
        if len(value) != 4:
            raise serializers.ValidationError("Exactly four choices are required.")
        return value
    
    def update(self, instance, validated_data):
        choices_data = validated_data.pop('choices')
        question_obj = Question.objects.get(id=instance.id)
        question_obj.title = validated_data.get('title', question_obj.title)
        question_obj.description = validated_data.get('description', question_obj.description)
        question_obj.save()

        for choice_data in choices_data:
            choice_data = dict(choice_data)
            choice_id = choice_data.get('id', None)
            choice_obj = Choice.objects.get(id=choice_id)
            choice_obj.choice_text = choice_data.get('choice_text', choice_obj.choice_text)
            choice_obj.is_correct = choice_data.get('is_correct', choice_obj.is_correct)
            choice_obj.save()
        return question_obj

class SubmissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Submission
        fields = '__all__'

class SubmissionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Submission
        fields='__all__'
    def create(self, validated_data):
        choice_id  = self.context['view'].kwargs['id']
        question_id = self.context['view'].kwargs['question_id']
        if not Choice.objects.filter(id=choice_id,question_id=question_id).exists():
            raise serializers.ValidationError("Choice does not exist.")
        try:
            submission = Submission.objects.get(quizinee=self.context['request'].user, question_id=question_id)
            submission.selected_choice_id = choice_id
        except:
            submission = Submission.objects.create(selected_choice_id=choice_id, quizinee=self.context['request'].user, question_id=question_id)
        submission.save()
        return submission