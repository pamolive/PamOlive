class SecurityHeadersMiddleware:
    PRODUCT_CSP = "; ".join(
        (
            "default-src 'self'",
            "base-uri 'self'",
            "connect-src 'self' ws: wss:",
            "font-src 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
            "img-src 'self' data:",
            "object-src 'none'",
            "script-src 'self'",
            "style-src 'self'",
        )
    )
    TECHNICAL_ADMIN_CSP = PRODUCT_CSP.replace(
        "script-src 'self'",
        "script-src 'self' 'unsafe-inline'",
    ).replace(
        "style-src 'self'",
        "style-src 'self' 'unsafe-inline'",
    )

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response["Content-Security-Policy"] = (
            self.TECHNICAL_ADMIN_CSP
            if request.path.startswith("/django-admin/")
            else self.PRODUCT_CSP
        )
        response["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        response["Referrer-Policy"] = "same-origin"
        return response
