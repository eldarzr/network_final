import random
import pandas as pd
from collections import defaultdict, Counter
import math
from scipy.stats import norm

class SpaceSaving:
    def __init__(self, k):
        self.k = k
        self.counters = Counter()
        self.min_counter = 0
        self.legit_traffic = Counter()  # Add counter for legitimate traffic

    def increment(self, item, legitimate=False):
        if legitimate:
            self.legit_traffic[item] += 1  # Track legitimate traffic
        if item in self.counters or len(self.counters) < self.k:
            self.counters[item] += 1
        else:
            min_item = min(self.counters, key=self.counters.get)
            self.min_counter = self.counters[min_item]
            self.counters.pop(min_item)
            self.counters[item] = self.min_counter + 1

    def get_counters(self):
        return self.counters

    def get_legit_traffic(self):
        return self.legit_traffic  # Retrieve legitimate traffic data

class RHHH:
    def __init__(self, hierarchy_levels, k, delta=0.05):
        self.hierarchy_levels = hierarchy_levels
        self.hh_algorithms = [SpaceSaving(k) for _ in range(hierarchy_levels)]
        self.V = hierarchy_levels
        self.delta = delta
        self.attack_detection_threshold = 0.05  # Set this based on your anomaly detection needs

    def update(self, packet, legitimate=False):
        level = random.randint(0, self.V - 1)
        prefix = self.get_prefix(packet, level)
        self.hh_algorithms[level].increment(prefix, legitimate=legitimate)

    def get_prefix(self, packet, level):
        parts = packet.split('.')
        pp = '.'.join(parts[:level + 1])
        return pp
    
    def func(self, pref):
        return sum([self.hh_algorithms[p_level].get_counters().get(pref, 0) for p_level in range(self.hierarchy_levels - 1, -1, -1)])


    def calc_pred(self, p, P):
        level = len(p.split('.')) - 1
        sum = 0
        for pref, count in P:
            if p == self.get_prefix(pref, level):
                p_level = len(pref.split('.')) - 1
                sum += self.hh_algorithms[p_level].get_counters().get(pref, 0)
        return -sum

    def output(self, theta):
        hhh_set = set()
        Z = norm.ppf(1 - self.delta / 2)
        N = sum(counter for hh in self.hh_algorithms for counter in hh.get_counters().values())

        for level in range(self.hierarchy_levels - 1, -1, -1):
            hh_counters = self.hh_algorithms[level].get_counters()
            for prefix, count in hh_counters.items():
                conditioned_frequency = count + self.calc_pred(prefix, hhh_set)
                adjusted_conditioned_frequency = conditioned_frequency + 2 * Z * math.sqrt(N * self.V)

                print(f"Prefix: {prefix}, Count: {count}, Conditioned Frequency: {conditioned_frequency}, "
                      f"Adjusted Conditioned Frequency: {adjusted_conditioned_frequency}, Threshold: {theta * N}")

                if adjusted_conditioned_frequency >= theta * N:
                    hhh_set.add((prefix,conditioned_frequency))
        return hhh_set

    def get_legitimate_traffic_sources(self):
        legitimate_sources = set()
        for level in range(self.hierarchy_levels):
            legit_traffic = self.hh_algorithms[level].get_legit_traffic()
            legitimate_sources.update(legit_traffic.keys())
        return legitimate_sources

    def detect_attack_sources(self, legitimate_sources):
        attack_sources = set()
        for level in range(self.hierarchy_levels):
            all_counters = self.hh_algorithms[level].get_counters()
            for prefix in all_counters:
                if prefix not in legitimate_sources:
                    attack_sources.add(prefix)
        return attack_sources


# # Example Usage
# hierarchy_levels = 4
# k = 10
# theta = 0.1
# delta = 0.05

# rhhh = RHHH(hierarchy_levels, k, delta)

# file_path = 'attacked.csv'
# dataset = pd.read_csv(file_path)

# packets = dataset['Source'].to_list()

# # Assume first 100 packets are legitimate
# for packet in packets[:1000]:
#     rhhh.update(packet, legitimate=True)

# # Rest packets are mixed (attack and legitimate)
# for packet in packets[1000:]:
#     rhhh.update(packet)

# hhh_result = rhhh.output(theta)
# print("Hierarchical Heavy Hitters:", hhh_result)

# legitimate_sources = rhhh.get_legitimate_traffic_sources()
# print("Legitimate Traffic Sources:", legitimate_sources)

# attack_sources = rhhh.detect_attack_sources(legitimate_sources)
# print("Potential Attack Sources:", attack_sources)
