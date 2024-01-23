import json

from rest_framework import renderers
from rest_framework import renderers
from drf_standardized_errors.formatter import ExceptionFormatter
from drf_standardized_errors.types import ErrorResponse


class UserRenderer(renderers.JSONRenderer):

   
   def render(self, data, accepted_media_type=None, renderer_context=None):
       if not renderer_context['response'].exception:
           data = {
               "success": True,
               "data": data
           }
        
       return super(UserRenderer, self).render(data, accepted_media_type, renderer_context)


class MyExceptionFormatter(ExceptionFormatter):
   def format_error_response(self, error_response: ErrorResponse):
       error = error_response.errors[0]
       if error_response.type == "validation_error" and error.attr != "non_field_errors" and error.attr is not None:
           error_message = f"{error.attr}: {error.detail}"
       else:
           error_message = error.detail
       return {
           "success": False,
           "type": error_response.type,
           "code": error.code,
           "error": error_message
       }