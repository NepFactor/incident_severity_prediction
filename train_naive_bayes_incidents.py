import csv
import math
import random
from collections import defaultdict, Counter

INPUT_FILE = "windows_incidents.csv"

# Expected columns in CSV:
# timestamp,event_id,account,process_name,group_name,
# privileged_logon,admin_group_touch,suspicious_process,time_bucket,burst_count,severity
#
# Make sure you've added a `severity` column with values like: low, medium, high.


# ---------------------------
# Helper: load and preprocess
# ---------------------------

def load_data(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            # Require severity and event_id
            sev = (r.get("severity") or "").strip().lower()
            eid = (r.get("event_id") or "").strip()
            if not sev or not eid:
                continue

            try:
                eid = int(eid)
            except ValueError:
                continue

            # Parse engineered features
            privileged = int(r.get("privileged_logon") or 0)
            admin_touch = int(r.get("admin_group_touch") or 0)
            suspicious = int(r.get("suspicious_process") or 0)
            time_bucket = (r.get("time_bucket") or "unknown").strip().lower()

            try:
                burst = float(r.get("burst_count") or 1.0)
            except ValueError:
                burst = 1.0

            rows.append({
                "event_id": eid,
                "privileged_logon": 1 if privileged else 0,
                "admin_group_touch": 1 if admin_touch else 0,
                "suspicious_process": 1 if suspicious else 0,
                "time_bucket": time_bucket,
                "burst_count": burst,
                "severity": sev,
            })
    return rows


# ---------------------------
# Train/test split
# ---------------------------

def train_test_split(rows, test_ratio=0.3, seed=42):
    random.Random(seed).shuffle(rows)
    n_test = max(1, int(len(rows) * test_ratio))
    test = rows[:n_test]
    train = rows[n_test:]
    return train, test


# ---------------------------
# Naive Bayes implementation
# ---------------------------

class NaiveBayesIncident:
    def __init__(self, alpha=1.0):
        self.alpha = alpha
        self.classes = []
        self.priors = {}  # P(C)
        # Likelihoods
        self.event_id_counts = {}      # P(event_id | C)
        self.event_id_vocab = set()
        self.time_bucket_counts = {}   # P(time_bucket | C)
        self.time_bucket_vocab = set()
        self.binary_counts = {}        # for Bernoulli: (feature, C) -> count(1)
        self.class_counts = {}         # count per class
        # Gaussian for burst_count
        self.burst_mean = {}
        self.burst_var = {}

    def fit(self, rows):
        # Collect class counts
        class_counts = Counter(r["severity"] for r in rows)
        self.classes = sorted(class_counts.keys())
        total = sum(class_counts.values())
        self.class_counts = dict(class_counts)

        # Priors
        self.priors = {c: class_counts[c] / total for c in self.classes}

        # Initialize containers
        self.event_id_counts = {c: Counter() for c in self.classes}
        self.time_bucket_counts = {c: Counter() for c in self.classes}
        self.binary_counts = {("privileged_logon", c): 0 for c in self.classes}
        self.binary_counts.update({("admin_group_touch", c): 0 for c in self.classes})
        self.binary_counts.update({("suspicious_process", c): 0 for c in self.classes})

        # For Gaussian
        burst_sums = {c: 0.0 for c in self.classes}
        burst_sq_sums = {c: 0.0 for c in self.classes}

        # Count occurrences
        for r in rows:
            c = r["severity"]
            eid = r["event_id"]
            tb = r["time_bucket"]
            self.event_id_counts[c][eid] += 1
            self.time_bucket_counts[c][tb] += 1
            self.event_id_vocab.add(eid)
            self.time_bucket_vocab.add(tb)

            if r["privileged_logon"] == 1:
                self.binary_counts[("privileged_logon", c)] += 1
            if r["admin_group_touch"] == 1:
                self.binary_counts[("admin_group_touch", c)] += 1
            if r["suspicious_process"] == 1:
                self.binary_counts[("suspicious_process", c)] += 1

            burst = r["burst_count"]
            burst_sums[c] += burst
            burst_sq_sums[c] += burst * burst

        # Bernoulli params & Gaussian params
        for c in self.classes:
            n_c = self.class_counts[c]
            # Gaussian for burst_count
            if n_c > 0:
                mean = burst_sums[c] / n_c
                var = (burst_sq_sums[c] / n_c) - mean * mean
                if var <= 0:
                    var = 1e-6  # avoid zero variance
            else:
                mean, var = 1.0, 1.0
            self.burst_mean[c] = mean
            self.burst_var[c] = var

    def _log_prob_event_id(self, eid, c):
        counts = self.event_id_counts[c]
        V = len(self.event_id_vocab) or 1
        num = counts[eid] + self.alpha
        den = self.class_counts[c] + self.alpha * V
        return math.log(num / den)

    def _log_prob_time_bucket(self, tb, c):
        counts = self.time_bucket_counts[c]
        V = len(self.time_bucket_vocab) or 1
        num = counts[tb] + self.alpha
        den = self.class_counts[c] + self.alpha * V
        return math.log(num / den)

    def _log_prob_binary(self, feature_value, feature_name, c):
        # Bernoulli with Laplace smoothing
        key = (feature_name, c)
        ones = self.binary_counts.get(key, 0)
        n_c = self.class_counts[c]
        # P(x=1|C)
        p1 = (ones + self.alpha) / (n_c + 2 * self.alpha)
        p0 = 1 - p1
        return math.log(p1 if feature_value == 1 else p0)

    def _log_prob_burst(self, burst, c):
        # Gaussian
        mu = self.burst_mean[c]
        var = self.burst_var[c]
        coef = -0.5 * math.log(2 * math.pi * var)
        exponent = -((burst - mu) ** 2) / (2 * var)
        return coef + exponent

    def predict_proba_row(self, r):
        eid = r["event_id"]
        tb = r["time_bucket"]
        burst = r["burst_count"]
        pl = r["privileged_logon"]
        ag = r["admin_group_touch"]
        sp = r["suspicious_process"]

        log_post = {}
        for c in self.classes:
            lp = math.log(self.priors[c])

            # event_id categorical
            lp += self._log_prob_event_id(eid, c)

            # time_bucket categorical
            lp += self._log_prob_time_bucket(tb, c)

            # binary features
            lp += self._log_prob_binary(pl, "privileged_logon", c)
            lp += self._log_prob_binary(ag, "admin_group_touch", c)
            lp += self._log_prob_binary(sp, "suspicious_process", c)

            # numeric burst_count
            lp += self._log_prob_burst(burst, c)

            log_post[c] = lp

        # normalize to probabilities
        max_lp = max(log_post.values())
        exps = {c: math.exp(log_post[c] - max_lp) for c in self.classes}
        z = sum(exps.values())
        return {c: exps[c] / z for c in self.classes}

    def predict_row(self, r):
        proba = self.predict_proba_row(r)
        return max(proba, key=proba.get)


# ---------------------------
# Metrics + main routine
# ---------------------------

def evaluate(model, test_rows):
    y_true = []
    y_pred = []
    for r in test_rows:
        true = r["severity"]
        pred = model.predict_row(r)
        y_true.append(true)
        y_pred.append(pred)

    classes = model.classes
    cm = {c: {c2: 0 for c2 in classes} for c in classes}
    for t, p in zip(y_true, y_pred):
        cm[t][p] += 1

    correct = sum(1 for t, p in zip(y_true, y_pred) if t == p)
    acc = correct / len(y_true) if y_true else 0.0

    print("=== Evaluation ===")
    print(f"Test samples: {len(y_true)}")
    print(f"Accuracy: {acc:.3f}\n")

    print("Confusion Matrix (rows=true, cols=pred):")
    header = "          " + " ".join(f"{c:>8}" for c in classes)
    print(header)
    for t in classes:
        row = f"{t:>8} "
        for p in classes:
            row += f"{cm[t][p]:8d}"
        print(row)
    print()

    # Precision / Recall per class
    print("Per-class Precision / Recall:")
    for c in classes:
        tp = cm[c][c]
        fp = sum(cm[t][c] for t in classes if t != c)
        fn = sum(cm[c][p] for p in classes if p != c)
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        print(f"{c:>8}: Precision={prec:.3f}, Recall={rec:.3f}")
    print()


def show_example_posteriors(model, test_rows, k=3):
    print("=== Example Posterior Probabilities ===")
    sample = test_rows[:k] if len(test_rows) >= k else test_rows
    for i, r in enumerate(sample, 1):
        proba = model.predict_proba_row(r)
        pred = max(proba, key=proba.get)
        print(f"Example {i}: "
              f"event_id={r['event_id']}, "
              f"priv={r['privileged_logon']}, "
              f"admin_grp={r['admin_group_touch']}, "
              f"suspicious={r['suspicious_process']}, "
              f"time={r['time_bucket']}, "
              f"burst={r['burst_count']:.1f}")
        for c in model.classes:
            print(f"   P({c}|X) = {proba[c]:.3f}")
        print(f"   Predicted severity: {pred}, True: {r['severity']}\n")


def main():
    rows = load_data(INPUT_FILE)
    if not rows:
        print("No valid rows found. Make sure event_id and severity are populated.")
        return

    print(f"Loaded {len(rows)} labeled rows from {INPUT_FILE}")
    train, test = train_test_split(rows, test_ratio=0.3)

    print(f"Train size: {len(train)}, Test size: {len(test)}\n")

    model = NaiveBayesIncident(alpha=1.0)
    model.fit(train)

    evaluate(model, test)
    if test:
        show_example_posteriors(model, test, k=min(3, len(test)))


if __name__ == "__main__":
    main()

