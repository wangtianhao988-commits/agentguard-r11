"""Evidence must contain actual caller locations without retaining locals."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'collector'))
from native_stack import capture


class NativeStackTests(unittest.TestCase):
    def test_real_caller_and_no_local_values(self):
        secret = 'must-not-appear-in-frame-evidence'
        result = capture()
        frames = result['threads'][0]['frames']
        self.assertEqual(frames[0]['fn'], 'test_real_caller_and_no_local_values')
        self.assertTrue(frames[0]['at'].startswith('test_native_stack.py:'))
        self.assertNotIn(secret, str(result))
        self.assertEqual(result['capture_method'], 'current-thread-live-frames')

    def test_bound_and_distinct_callers(self):
        def tool_dispatch():
            return capture(2)
        frames = tool_dispatch()['threads'][0]['frames']
        self.assertEqual(len(frames), 2)
        self.assertEqual(frames[0]['fn'], 'tool_dispatch')
        self.assertEqual(frames[1]['fn'], 'test_bound_and_distinct_callers')


if __name__ == '__main__':
    unittest.main(verbosity=2)
