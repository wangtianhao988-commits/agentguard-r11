"""Optional transparent verifier instrumentation; never changes authentication.

Only error class and numeric timestamps are recorded. Unverified claims are marked
as such and used for diagnosis, never for identity or permission decisions.
"""
import base64
import functools
import json
import time
from datetime import datetime, timezone

def instrument(verifier, record):
    @functools.wraps(verifier)
    def wrapped(*args, **kwargs):
        try:
            return verifier(*args, **kwargs)
        except Exception as error:
            try:
                evidence = {'error_class': type(error).__name__,
                            'wall_clock_s': time.time(),
                            'verification_clock_s': datetime.now(timezone.utc).timestamp(),
                            'unverified_claims': True}
                token = args[0] if args else kwargs.get('token')
                if isinstance(token, str) and len(token) <= 8192:
                    try:
                        segment = token.split('.')[1]
                        claims = json.loads(base64.urlsafe_b64decode(segment+'='*((-len(segment))%4)))
                        for key in ['iat', 'nbf', 'exp']:
                            value = claims.get(key)
                            if isinstance(value, (int, float)) and not isinstance(value, bool):
                                evidence['claimed_'+key] = value
                    except (IndexError, ValueError, TypeError, AttributeError):
                        pass
                record(evidence)
            except Exception:
                # Diagnostics cannot convert a rejected token into an accepted one
                # or obscure the verifier's original exception type/identity.
                pass
            raise
    return wrapped
