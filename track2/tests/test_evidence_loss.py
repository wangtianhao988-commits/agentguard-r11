import sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'collector'),str(ROOT/'detector')]
from gateway import EvidenceStore

class LossTests(unittest.TestCase):
    def test_serialization_failure_is_visible_in_health_drop_counts(self):
        class Malformed:
            def __str__(self):raise ValueError('invalid audit object')
        with tempfile.TemporaryDirectory() as folder:
            store=EvidenceStore(folder)
            store.write('broken',{'object':Malformed()})
            self.assertEqual(store.dropped(),{'broken':1})
            store.write('normal',{'event':'complete'});store.flush_all()
            self.assertIn('complete',(Path(folder)/'normal.jsonl').read_text());store.close()

if __name__=='__main__':unittest.main()
