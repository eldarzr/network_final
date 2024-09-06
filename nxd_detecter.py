from collections import defaultdict, deque
from hhh import RHHH
import pandas as pd

class DNSProtection:
    def __init__(self, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio, lower_attack_threshold_ratio,
                  upper_attack_threshold_ratio,hierarchy_levels, aging, k, list_expiry_limit):
        self.aging = aging
        self.upper_threshold_nxd_ratio = upper_threshold_nxd_ratio
        self.lower_threshold_nxd_ratio = lower_threshold_nxd_ratio
        self.upper_attack_threshold_ratio = upper_attack_threshold_ratio
        self.lower_attack_threshold_ratio = lower_attack_threshold_ratio
        self.list_expiry_limit = list_expiry_limit
        self.rh_legit = RHHH(hierarchy_levels, k, aging)
        self.rh_attack = RHHH(hierarchy_levels, k, aging)
        self.total_queries = 0
        self.queries = 0
        self.total_nxd = 0
        self.nxd = 0
        self.tp = 0
        self.fp = 0
        self.tn = 0
        self.fn = 0
        self.under_attack = False
        self.debug_log = []

    def log_normal_traffic(self, packet):
        source = packet['Source']
        self.rh_legit.update(source, legitimate=True)

    def packet_allowed(self, packet):
        source = packet['Source']
        
        # Clean up expired entries from blacklist and whitelist
        self.cleanup_lists()

        if self.should_block(source):
            return "Block"
        else:
            return "Allow"

    def process_packet(self, packet):
        alowed = self.packet_allowed(packet)
        source = packet['Source']

        self.total_queries += 1
        self.queries += 1

        nxd_flg = self.is_nxd(packet)

        if alowed == 'Allow':
            if nxd_flg:
                self.total_nxd += 1
                self.nxd += 1
                self.rh_attack.update(source)
            else:
                self.log_normal_traffic(packet)

            if not nxd_flg:
                self.tp += 1
            if nxd_flg:
                self.fp += 1

        if alowed == 'Block':
            if nxd_flg:
                self.tn += 1
            if not nxd_flg:
                self.fn += 1

        return alowed

    def is_nxd(self, packet):
        return packet['Legitimate'] == 'False' or packet['Legitimate'] == False

    def is_under_attack(self):
        if self.queries == 0:
            return False
        current_nxd_ratio = self.nxd / self.queries
        if current_nxd_ratio < self.lower_threshold_nxd_ratio:
            self.under_attack = False
        if current_nxd_ratio >= self.upper_threshold_nxd_ratio:
            self.under_attack = True
        return self.under_attack

    def should_block(self, source):
        legit_freq = self.rh_legit.get_prefix_count(source)
        attack_freq = self.rh_attack.get_prefix_count(source)

        if self.is_under_attack():
            legit_freq *= self.lower_attack_threshold_ratio
        else:
            legit_freq *= self.upper_attack_threshold_ratio
        # Compare adjusted conditioned frequencies
        return attack_freq > legit_freq

    def cleanup_lists(self):
        # Remove expired entries from blacklist
        if self.total_queries % self.list_expiry_limit == 0:
            self.queries = int(self.queries * self.aging)
            self.nxd = int(self.nxd * self.aging)
            self.rh_legit.decrease()
            self.rh_attack.decrease()

def simulate_attack(hierarchy_levels, upper_threshold_nxd_ratio, lower_threshold_nxd_ratio,
                    upper_attack_threshold_ratio, lower_attack_threshold_ratio, list_expiry_limit,
                    aging, k, packets):
    dns_protection = DNSProtection(
        upper_threshold_nxd_ratio=upper_threshold_nxd_ratio, 
        lower_threshold_nxd_ratio=lower_threshold_nxd_ratio, 
        upper_attack_threshold_ratio=upper_attack_threshold_ratio, 
        lower_attack_threshold_ratio=lower_attack_threshold_ratio, 
        hierarchy_levels=hierarchy_levels, 
        aging=aging, 
        k=k, 
        list_expiry_limit=list_expiry_limit  
    )

    for packet in packets:
        _ = dns_protection.process_packet(packet)
    return dns_protection
