 # 🔍 Malicious Link Finder

  A lightweight GUI-based Python tool to detect **malicious**, **phishing**, or **suspicious** websites using multiple heuristics and VirusTotal API. Built with `customtkinter`.

  ---

  ## 📁 1. Clone the Repository

  ```bash
  git clone https://github.com/karteek0432/malicious_link_finder.git
  cd malicious_link_finder
  ```

  ---

  ## 📦 2. Install Dependencies

  Make sure you have Python 3.8+ installed, then run:

  ```bash
  pip install customtkinter requests tldextract pillow
  ```

  ---

  ## 🔐 3. Configuration

  Set your [VirusTotal API key](https://www.virustotal.com/gui/join-us) as an environment variable:

  **Windows (Command Prompt):**

  ```bash
  set API_KEY=your_api_key_here
  ```

  **Linux/macOS (Terminal):**

  ```bash
  export API_KEY=your_api_key_here
  ```

  ---

  ## 🚀 4. Usage

  Run the tool with:

  ```bash
  python malicious_link_finder.py
  ```

  - Paste or type a URL into the field.
  - Click **"Scan Website"**.
  - You'll see a color-coded result:
    - ✅ Green = Safe
    - 🔵 Blue = Educational/Test
    - 🔴 Red = Malicious
    - 🟠 Orange = Suspicious

  ---

  ## 📚 5. Features

  - ✅ VirusTotal integration
  - 🔍 Heuristic phishing detection
  - 🚨 Manual blacklist support
  - 🧠 Detects educational/test sites
  - 🌗 Dark/light mode toggle
  - 📋 Paste from clipboard button

  ---

  ## ⚠️ 6. Disclaimer

  This tool is intended **only for educational and testing purposes**.  
  **Do not use** it for unethical or unauthorized scanning.

  ---

  ## 🛠 Author

  **Rokkam Karteek**  
  📧 karteekrokkamsk@gmail.com  
  🔗 [GitHub](https://github.com/karteek0432) | [LinkedIn](https://www.linkedin.com/in/karteek-rokkam/)
