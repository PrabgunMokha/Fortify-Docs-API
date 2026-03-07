

import streamlit as st
import requests
import io

API_BASE = "http://localhost:8000/api/v1/documents"

st.set_page_config(page_title="🔐 Password Secured File", page_icon="🔐")
st.title("🔐 Password Secured File")
st.caption("Protect your PDFs & Images with password-based encryption")

tab_protect, tab_unlock = st.tabs(["🔒 Protect", "🔓 Unlock"])

with tab_protect:
    uploaded = st.file_uploader(
        "Upload PDF or Image",
        type=["pdf", "jpg", "jpeg", "png", "bmp", "tiff", "tif", "gif", "webp"],
        key="protect_file",
    )

    password = st.text_input("Set Password (min 4 chars)", type="password", key="p1")
    confirm = st.text_input("Confirm Password", type="password", key="p2")

    if uploaded:
        ext = uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else ""
        if ext != "pdf":
            st.info("� Your image will be automatically converted to a password-protected PDF")

    if st.button("🔐 Protect File", use_container_width=True):
        if not uploaded:
            st.error("Upload a file first!")
        elif not password or len(password) < 4:
            st.error("Password must be at least 4 characters!")
        elif password != confirm:
            st.error("Passwords do not match!")
        else:
            with st.spinner("Protecting..."):
                try:
                    resp = requests.post(
                        f"{API_BASE}/protect",
                        files={"file": (uploaded.name, uploaded.getvalue(), uploaded.type)},
                        data={"password": password},
                        timeout=60,
                    )
                    if resp.status_code == 200:
                        cd = resp.headers.get("Content-Disposition", "")
                        fname = cd.split("filename=")[1].strip('"') if "filename=" in cd else "protected_file"
                        st.success("✅ File protected!")
                        st.download_button("⬇️ Download", resp.content, fname, resp.headers.get("Content-Type", "application/octet-stream"))
                    else:
                        st.error(resp.json().get("detail", "Error"))
                except requests.ConnectionError:
                    st.error("❌ Server not running! Start with: `uvicorn main:app --reload --port 8000`")

with tab_unlock:
    locked_file = st.file_uploader(
        "Upload protected file",
        type=["pdf", "enc"],
        key="unlock_file",
    )

    unlock_pw = st.text_input("Enter Password", type="password", key="unlock_pw")

    if st.button("🔓 Unlock File", use_container_width=True):
        if not locked_file:
            st.error("Upload a file first!")
        elif not unlock_pw:
            st.error("Enter the password!")
        else:
            with st.spinner("Unlocking..."):
                try:
                    resp = requests.post(
                        f"{API_BASE}/unlock",
                        files={"file": (locked_file.name, locked_file.getvalue(), "application/octet-stream")},
                        data={"password": unlock_pw},
                        timeout=60,
                    )
                    if resp.status_code == 200:
                        cd = resp.headers.get("Content-Disposition", "")
                        fname = cd.split("filename=")[1].strip('"') if "filename=" in cd else "unlocked_file"
                        st.success("✅ File unlocked!")
                        st.download_button("⬇️ Download", resp.content, fname, resp.headers.get("Content-Type", "application/octet-stream"))
                    elif resp.status_code == 401:
                        st.error("🔒 Wrong password!")
                    else:
                        st.error(resp.json().get("detail", "Error"))
                except requests.ConnectionError:
                    st.error("❌ Server not running! Start with: `uvicorn main:app --reload --port 8000`")
