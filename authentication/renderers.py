import json

from rest_framework import renderers


class UserRenderer(renderers.JSONRenderer):
    charset = "utf-8"

    def render(self, data, accepted_media_type=None, renderer_context=None):
        response = ""

        # Check if the response status code indicates an error
        if 400 <= renderer_context["response"].status_code < 600:
            first_key = list(data.keys())[0]
            f = data[first_key]
            response = json.dumps(
                {"success": False, "message": f[0]
                    if isinstance(f, list) else f}
            )

        else:
            if "data" not in data:
                response = json.dumps(
                    {"success": True, "message": data["message"]})
            else:
                response = json.dumps(
                    {"success": True,
                        "message": data["message"], "data": data["data"]}
                )

        return response
