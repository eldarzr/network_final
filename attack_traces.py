import pandas as pd
import random
import string

# Load the original dataset
def load_data(file_path):
    return pd.read_csv(file_path)

# Generate fake domain names
def generate_fake_prefixes():
    domains = ["example", "mywebsite", "coolsite", "techblog", "superapp", "newsite", "learncode", "shopnow", "musicworld", "foodies"]
    tlds = [".com", ".net", ".org", ".co", ".io"]
    paths = ["about", "contact", "products", "services", "blog", "home", "portfolio", "login", "signup", "news"]
    
    urls = []
    for domain in domains:
        path = random.choice(paths)
        tld = random.choice(tlds)
        url = f"https://{domain}{tld}/{path}"
        urls.append(url)
    
    return urls

# Function to return a specified number of distinct elements
def generate_ndx(num):
    return random.sample(generate_fake_prefixes(), num)

# Generate fake domain names
def generate_fake_domain(name):
    known_domains = ["google.com", "amazonaws.com", "akamai.net", "facebook.com", "microsoft.com"]
    prefix = random.choice(["malicious", "fake", "phishing", "bad"])
    domain = random.choice(known_domains)
    return f"{prefix}.{name}.{domain}"

def generate_botnets(data, botnet_num, shared_subnet):
    ex_ip = data['Source'].drop_duplicates()
    sub = ex_ip.sample().iloc[0].split('.')[:shared_subnet]
    ret = []
    for _ in range(botnet_num):
        ip = sub.copy()
        while len(ip) < 4:
            ip.append(str(random.randint(0,255)))
        ret.append('.'.join(ip))
    return ret, '.'.join(sub)


# Generate attacker records
def generate_attacker_records(original_data, num_records, attack_range, start, botnet_num, shared_subnet, nxd_num):
    attacker_data = []
    splitted_data = original_data[start:num_records]
    record = splitted_data.sample().iloc[0]
    botnets_addresses, subnet = generate_botnets(original_data, botnet_num, shared_subnet)
    botnets_nxd = generate_ndx(botnet_num)
    botnets = list(zip(botnets_addresses, botnets_nxd))

    for _ in range(int(num_records*attack_range)):
        source, fake_name = random.choice(botnets)
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

def create_attack_dataset(packets_num, botnet_num, shared_subnet, attack_packets_num, nxd_num, legit_volume):
    original_data = load_data('new_ip.csv')
    attacker_data, botnets, subnet = generate_attacker_records(original_data, packets_num, attack_packets_num, int(packets_num * legit_volume), botnet_num, shared_subnet, nxd_num)
    combined_data = combine_data(original_data, attacker_data)
    sorted_dataset = combined_data.sort_values(by='Time')
    return sorted_dataset, botnets, subnet

