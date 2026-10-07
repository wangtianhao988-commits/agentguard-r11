"""Fast observation decoding without integer-to-float coercion.

Use the pinned msgspec decoder when available. Unlike a lossy 64-bit decoder,
JSON integers remain arbitrary-precision Python ints. The standard decoder is
retained for legacy encodings/nonstandard values, preserving existing behavior.
Wire bytes and control-policy serialization are never rewritten by this helper.
"""
import json
try:
    import msgspec
except ImportError:
    msgspec=None
_DECODE=msgspec.json.decode if msgspec and msgspec.__version__=='0.21.1' else None
BACKEND='msgspec-0.21.1' if _DECODE else 'stdlib'

def loads(value):
    if _DECODE:
        try:return _DECODE(value)
        except (ValueError,TypeError,UnicodeError,RecursionError):pass
    return json.loads(value)

def response_json(response):
    # Honor an explicitly non-UTF8 HTTP encoding and Requests' own fallback.
    encoding=(response.encoding or '').lower().replace('_','-')
    if encoding not in {'utf-8','utf8'}:return response.json()
    return loads(response.content)
