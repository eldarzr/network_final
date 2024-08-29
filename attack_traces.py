import pandas as pd
import random
import string

# Load the original dataset
def load_data(file_path):
    return pd.read_csv(file_path)

def generate_random_string(length):
    """Generate a random string of a given length."""
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def generate_random_url(domain_length, req_length, tld=".com"):
    """Generate a random URL with the specified domain length and TLD."""
    domain = generate_random_string(domain_length)
    req = generate_random_string(req_length)
    return f"http://{domain}{tld}/{req}"

def generate_nxd_urls(num_urls, domain_length=10, req_length=10):
    """Generate a list of randomized URLs that mimic NXD attacks."""
    urls = [generate_random_url(domain_length, req_length) for _ in range(num_urls)]
    return urls

def generate_botnets(data, botnet_num, shared_subnet, subnet_num):
    ex_ip = data['Source'].drop_duplicates().to_list()
    rand_ip = random.sample(ex_ip, subnet_num)
    ret = []
    subs = []
    for sub in rand_ip:
        sub = sub.split('.')[:shared_subnet]
        subs.append('.'.join(sub))
        for __ in range(botnet_num):
            ip = sub.copy()
            while len(ip) < 4:
                ip.append(str(random.randint(0,255)))
            ret.append('.'.join(ip))
    return ret, subs


# Generate attacker records
def generate_attacker_records(original_data, num_records, attack_range, start, botnet_num, shared_subnet, subnet_num, nxd_num):
    attacker_data = []
    splitted_data = original_data[start:num_records]
    record = splitted_data.sample().iloc[0]
    botnets_addresses, subnet = generate_botnets(original_data, botnet_num, shared_subnet, subnet_num)
    botnets_nxd = generate_nxd_urls(botnet_num)
    print('*********************')
    print(botnets_nxd)
    print('*********************')
    # botnets = list(zip(botnets_addresses, botnets_nxd))

    for _ in range(int(num_records*attack_range)):
        source = random.choice(botnets_addresses)
        fake_name = random.choice(botnets_nxd)
        record = splitted_data.sample().iloc[0]
        # fake_name = generate_fake_domain(record['Name'])
        attacker_record = [record['Time'], source, record['Destination'], fake_name, False]
        attacker_data.append(attacker_record)
    return attacker_data, botnets_addresses, subnet

# Combine original data with attacker data
def combine_data(original_data, attacker_data):
    original_data['Legitimate'] = True
    attacker_df = pd.DataFrame(attacker_data, columns=['Time', 'Source', 'Destination', 'Name', 'Legitimate'])
    combined_data = pd.concat([original_data, attacker_df], ignore_index=True)
    return combined_data

def create_attack_dataset(packets_num, botnet_num, shared_subnet, subnet_num, attack_packets_num, nxd_num, legit_volume):
    original_data = load_data('new_ip.csv')
    attacker_data, botnets, subnet = generate_attacker_records(original_data, packets_num, attack_packets_num, int(packets_num * legit_volume), botnet_num, shared_subnet, subnet_num, nxd_num)
    combined_data = combine_data(original_data[:packets_num], attacker_data)
    sorted_dataset = combined_data.sort_values(by='Time')
    return sorted_dataset, botnets, subnet

