import random
import pandas as pd

def save_samples():
    # Load the large dataset
    file_path = 'dns_traces.csv'
    large_dataset = pd.read_csv(file_path)

    # Condition to drop rows where 'Length' > 1000
    condition = large_dataset['Source'].str.contains('[a-zA-Z]', case=True, na=False)

    # Drop rows that meet the condition
    cleaned_dataset = large_dataset[~condition]


    # Randomly sample 1% of the data (adjust the fraction as needed)
    sampled_dataset = cleaned_dataset.sample(frac=0.01, random_state=42)

    # Sort the sampled dataset by a specific column, e.g., 'Time'
    sorted_sampled_dataset = sampled_dataset.sort_values(by='Time')

    # Save the smaller dataset to a new CSV file
    small_file_path = 'attacked.csv'
    sorted_sampled_dataset.to_csv(small_file_path, index=False)

    print(f"Sampled dataset saved as '{small_file_path}'")

def save_subnets():
    # Load the large dataset
    file_path = 'dns_traces.csv'
    dataset = pd.read_csv(file_path)

    unique_values = dataset['Source'].drop_duplicates()

    # Condition to drop rows where 'Length' > 1000
    condition = dataset['Source'].str.contains('[a-zA-Z]', case=True, na=False)

    # Drop rows that meet the condition
    filtered_dataset = unique_values[~condition]

    unique_values_df = filtered_dataset.to_frame()
    sources_file_path = 'sources.csv'
    unique_values_df.to_csv(sources_file_path, index=False)

    print(f"sources dataset saved as '{sources_file_path}'")

# save_samples()

def generate_random_ip():
    """Generate a random IP address."""
    return '.'.join(str(random.randint(0, 255)) for _ in range(4))

def map_ips_to_random():
    """
    Map each IP address in the input list to a new random IP address.

    Args:
    ips (list of str): List of original IP addresses.

    Returns:
    dict: A dictionary mapping each original IP to a new random IP.
    """
    original_data = pd.read_csv('small_dns_traces.csv')
    ips = original_data['Source'].unique()
    new_ip = {ip: generate_random_ip() for ip in ips}
    original_data['Source'] = original_data['Source'].replace(new_ip)
    small_file_path = 'new_ip.csv'
    original_data.to_csv(small_file_path, index=False)

    print()

map_ips_to_random()
