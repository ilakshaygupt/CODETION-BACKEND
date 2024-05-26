# permissions.py

from rest_framework import permissions

from quiz.models import Question, Quiz, RegisteredParticipant
import operator
from functools import reduce

from django.db.models import Q
from django.shortcuts import get_object_or_404

class IsQuizAdmin(permissions.BasePermission):
    """
    Custom permission to only allow quiz admin to update and delete the quiz.
    """

    def has_permission(self, request, view):
        try:
            quiz_id = view.kwargs.get('id')
            quiz = Quiz.objects.get(id=quiz_id)
            return request.user == quiz.admin
        except Quiz.DoesNotExist:
            return False
        
class CanChangeQuestion(permissions.BasePermission):
    """
    Custom permission to only allow quiz admin to update and delete the quiz.
    """

    def has_permission(self, request, view):
        try:
            quiz_id = view.kwargs.get('quiz_id')
            quiz = Quiz.objects.get(id=quiz_id)
            return request.user == quiz.admin
        except Quiz.DoesNotExist:
            return False
class IsQuizAdminOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow quiz admin to update and delete the quiz.
    """

    def has_permission(self, request, view):
        try:
            quiz_id = view.kwargs.get('quiz_id')
            quiz = Quiz.objects.get(id=quiz_id)
            if quiz.admin == request.user:
                return True
            return RegisteredParticipant.objects.filter(quiz=quiz, user=request.user).exists()
        except Quiz.DoesNotExist:
            return False
        

class AllowAny(permissions.BasePermission):
    """
    Custom permission to allow any request.
    """

    def has_permission(self, request, view):
        return True

class MultipleFieldLookupMixin:
    """
    Apply this mixin to any view or viewset to get multiple field filtering
    based on a `lookup_fields` attribute, instead of the default single field filtering.
    """

    def get_object(self):
        queryset = self.get_queryset()             
        queryset = self.filter_queryset(queryset)  
        filter = {}
        for field in self.lookup_fields:
            if self.kwargs.get(field): 
                filter[field] = self.kwargs[field]
        obj = get_object_or_404(queryset, **filter)  
        self.check_object_permissions(self.request, obj)
        return obj