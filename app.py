import streamlit as st
import pandas as pd
import numpy as np
import time

# Function to simulate DDoS attack
def simulate_ddos(attack_intensity, num_subnets, overlap_ratio):
    dns_requests = np.random.poisson(lam=50, size=1000)
    attack_traffic = np.random.poisson(lam=attack_intensity, size=1000)
    overlap_traffic = int(overlap_ratio * len(attack_traffic))
    attack_traffic[:overlap_traffic] = dns_requests[:overlap_traffic]
    return dns_requests, attack_traffic

# Main app function
def main():
    st.title('DNS DDoS Attack Simulation and HHH Explanation')
    
    st.header('Task 7: DDoS Attack Simulation')
    
    attack_intensity = st.slider('Attack Intensity (packets/sec)', 10, 1000, 100)
    num_subnets = st.slider('Number of Attacking Subnets', 1, 10, 3)
    overlap_ratio = st.slider('Overlap Ratio with Legitimate Traffic', 0.0, 1.0, 0.5)
    
    if st.button('Start Simulation'):
        with st.spinner('Simulating DDoS attack...'):
            dns_requests, attack_traffic = simulate_ddos(attack_intensity, num_subnets, overlap_ratio)
            time.sleep(2)
        st.success('Simulation Complete!')
        
        st.subheader('DNS Traffic Status')
        st.line_chart(pd.DataFrame({'Legitimate Traffic': dns_requests, 'Attack Traffic': attack_traffic}))

    st.header('Task 8: Explanation of Hierarchical Heavy Hitters (HHH)')
    
    st.markdown("""
    **Hierarchical Heavy Hitters (HHH)**:
    
    The HHH algorithm is used to identify frequent flow aggregates based on common IP prefixes, crucial for detecting DDoS attacks.
    
    **How it works**:
    
    1. **Prefix-based Hierarchy**: HHH monitors traffic and groups it based on hierarchical IP prefixes.
    2. **Detection**: By analyzing traffic patterns, HHH can identify abnormal spikes in specific IP prefixes indicative of a DDoS attack.
    3. **Efficiency**: The algorithm runs in constant time, making it suitable for high-speed networks.
    
    **Example Results**:
    
    - **Legitimate Traffic**: Normal distribution of DNS requests.
    - **Attack Traffic**: Significant spike in traffic from certain IP prefixes.
    """)

if __name__ == "__main__":
    main()
