import copy
import json
import unittest
from pathlib import Path
from app.evaluate_detection import evaluate

class DetectionEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((Path(__file__).parent / "fixtures/detection-v1.json").read_text())
    def test_known_classifier_and_unmeasured_reviews(self):
        r = evaluate(self.data)
        self.assertEqual([r[k] for k in ("tp", "fp", "tn", "fn")], [4, 0, 5, 0])
        self.assertEqual(r["analyst_outcomes"]["pending"], 9)
        self.assertIsNone(r["mean_review_effort_seconds"])
    def test_false_positives_and_negatives_are_retained(self):
        self.data["cases"][0]["expected_positive"] = False
        self.data["cases"][-1]["expected_positive"] = True
        r = evaluate(self.data)
        self.assertEqual((r["fp"], r["fn"]), (1, 1))
        self.assertLess(r["accuracy"], 1)
    def test_review_outcomes_and_effort(self):
        self.data["cases"][0]["analyst_review"] = {"outcome": "confirmed", "effort_seconds": 12}
        self.assertEqual(evaluate(self.data)["mean_review_effort_seconds"], 12)
    def test_empty_duplicate_invalid_label_and_effort(self):
        variants = [dict(self.data, cases=[]), dict(self.data, cases=self.data["cases"] * 2)]
        for field, value in [("expected_positive", 1), ("analyst_review", {"outcome": "confirmed", "effort_seconds": float("nan")})]:
            d = copy.deepcopy(self.data); d["cases"][0][field] = value; variants.append(d)
        for d in variants:
            with self.assertRaises(ValueError): evaluate(d)
