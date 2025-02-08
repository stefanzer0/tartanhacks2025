import streamlit as st
import requests

st.title("🔍 OSINT Search Demo")

email = st.text_input("Enter Email:")
ip = st.text_input("Enter IP Address:")

if st.button("Search"):
    query_params = {"email": email, "ip": ip}
    response = requests.get("http://localhost:8000/osint_search", params=query_params)
    st.json(response.json())
