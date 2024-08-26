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
    def __init__(self, hierarchy_levels, k, aging=0.5, delta=0.05):
        self.aging = aging
        self.hierarchy_levels = hierarchy_levels
        self.hh_algorithms = [SpaceSaving(k) for _ in range(hierarchy_levels)]
        self.V = hierarchy_levels
        self.delta = delta
        self.attack_detection_threshold = 0.05  # Set this based on your anomaly detection needs

    def update(self, packet, legitimate=False):
        level = random.randint(0, self.V-1)
        prefix = self.get_prefix(packet, level)
        self.hh_algorithms[level].increment(prefix, legitimate=legitimate)

    def get_prefix(self, packet, level):
        parts = packet.split('.')
        pp = '.'.join(parts[:level+1])
        return pp
    
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

    def get_prefix_count(self, pref):
        return sum([self.hh_algorithms[p_level].get_counters().get(self.get_prefix(pref, p_level), 0) for p_level in range(0, self.hierarchy_levels)])
        # return sum([self.hh_algorithms[p_level].get_counters().get(pref, 0) for p_level in range(self.hierarchy_levels - 1, -1, -1)])

    def decrease(self):
        for level in range(0, self.hierarchy_levels):
            hh_counters = self.hh_algorithms[level].get_counters()
            for prefix in hh_counters.keys():
                hh_counters[prefix] = int(hh_counters[prefix] * self.aging)
