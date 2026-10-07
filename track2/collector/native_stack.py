"""Capture the calling worker's live Python frames without a subprocess.

Called synchronously before a risky tool request is forwarded. Frame objects and
locals never leave this function; only code locations are retained as evidence.
"""
import os
import sys
import threading
import time


def capture(max_frames=40):
    started = time.perf_counter()
    frames = []
    frame = sys._getframe(1)
    try:
        while frame is not None and len(frames) < max_frames:
            code = frame.f_code
            frames.append({'fn': code.co_name,
                           'at': f'{os.path.basename(code.co_filename)}:{frame.f_lineno}',
                           'file': code.co_filename})
            frame = frame.f_back
    finally:
        del frame
    return {'capture_method': 'current-thread-live-frames', 'pid': os.getpid(),
            'n_threads': 1, 'threads': [{'thread': threading.current_thread().name,
            'thread_id': threading.get_ident(), 'active': True, 'frames': frames}],
            'took_ms': (time.perf_counter()-started)*1000}
