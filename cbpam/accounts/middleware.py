from django.utils import translation


class UserLanguageMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(request, "user", None) and request.user.is_authenticated:
            language = request.user.preferred_language
        else:
            language = request.session.get("preferred_language", "fr")
        with translation.override(language):
            request.LANGUAGE_CODE = language
            return self.get_response(request)
