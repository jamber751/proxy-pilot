"""Source preparation refusal + deterministic interleaving, no network/GOST."""
from pathlib import Path
import importlib.util
import json
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('atomic_source',ROOT/'app/vpn-bridge/prepare_atomic_gost.py')
source=importlib.util.module_from_spec(spec);spec.loader.exec_module(source)

class PreparationTests(unittest.TestCase):
    def test_wrong_module_sum_refused_before_source_access(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);record=root/'download.json';destination=root/'candidate'
            record.write_text(json.dumps({'Path':'github.com/go-gost/x','Version':'v0.8.1','Sum':'changed','Dir':'/does-not-exist'}))
            with self.assertRaisesRegex(ValueError,'modulePin'):source.prepare(record,destination)
            self.assertFalse(destination.exists())

    def test_changed_source_refused_before_destination_creation(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);upstream=root/'source';upstream.mkdir();record=root/'download.json';destination=root/'candidate'
            for name in source.PREIMAGES:
                path=upstream/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'changed')
            record.write_text(json.dumps({'Path':'github.com/go-gost/x','Version':source.VERSION,'Sum':source.MODULE_SUM,'Dir':str(upstream)}))
            with self.assertRaisesRegex(ValueError,'sourcePreimage'):source.prepare(record,destination)
            self.assertFalse(destination.exists())

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);destination=root/'candidate';destination.mkdir();marker=destination/'keep';marker.write_bytes(b'keep')
            record=root/'download.json';record.write_text(json.dumps({'Path':'github.com/go-gost/x','Version':source.VERSION,'Sum':source.MODULE_SUM,'Dir':str(root)}))
            with self.assertRaisesRegex(ValueError,'destination'):source.prepare(record,destination)
            self.assertEqual(marker.read_bytes(),b'keep')

    def test_two_alternating_lists_are_insufficient_for_a_paused_reader(self):
        # Mirrors the pinned group's separate Contains(A), Contains(B) reads.
        # There is always a live covering list, yet ONE paused reader misses both.
        live={'A':True,'B':True}
        live['A']=False
        first=live['A']
        self.assertTrue(any(live.values()))
        live['A']=True
        live['B']=False
        second=live['B']
        self.assertTrue(any(live.values()))
        self.assertFalse(first or second)

if __name__=='__main__':unittest.main()
