# ui/components/search_bar.py
# GOAL: Render the search bar where the user types an IP address
# Validates the input before sending it to the lookup function

import streamlit as st
import re

def is_valid_ip(ip_string):
    """
    Checks if the string looks like a valid IPv4 address.
    Example: "192.168.1.1" → True
             "hello"       → False
             "999.1.1.1"   → False
    """
    # Regex pattern for IPv4: four groups of 1-3 digits separated by dots
    pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
    match = re.match(pattern, ip_string.strip())

    if not match:
        return False

    # Each part must be between 0 and 255
    parts = [int(match.group(i)) for i in range(1, 5)]
    return all(0 <= part <= 255 for part in parts)


def render_search_bar():
    """
    Renders the IP search bar in the Streamlit UI.
    Returns the IP address string if the user clicked Search, otherwise returns None.
    """

    st.markdown("### 🔍 IP Threat Lookup")
    st.markdown("Enter an IP address to check its abuse reputation and threat level.")

    # Two columns: input field on the left, button on the right
    col1, col2 = st.columns([4, 1])

    with col1:
        ip_input = st.text_input(
            label="IP Address",
            placeholder="e.g. 8.8.8.8",
            label_visibility="collapsed"   # hides the label, placeholder does the job
        )

    with col2:
        search_clicked = st.button("🔎 Search", use_container_width=True)

    # Only proceed if the button was clicked
    if search_clicked:
        if not ip_input.strip():
            st.warning("⚠️ Please enter an IP address.")
            return None

        if not is_valid_ip(ip_input.strip()):
            st.error("❌ Invalid IP address format. Please enter a valid IPv4 address (e.g. 192.168.1.1)")
            return None

        return ip_input.strip()

    return None


# --- TEST (run with: streamlit run search_bar.py) ---
if __name__ == "__main__":
    st.set_page_config(page_title="Search Bar Test", layout="centered")
    st.title("Search Bar Component Test")

    result = render_search_bar()

    if result:
        st.success(f"Valid IP entered: `{result}`")