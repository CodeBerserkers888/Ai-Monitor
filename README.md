<h1 align="center" id="title">Ai-Monitor</h1>

<p align="center"><img src="https://socialify.git.ci/CodeBerserkers888/Ai-Monitor/image?description=1&descriptionEditable=%20AI-Secure%20Monitor%20your%20all-in-one%20solution%20for%20monitoring%20and%20securing%20your%20PC.%20&font=Source%20Code%20Pro&language=1&logo=https%3A%2F%2Fzapodaj.net%2Fimages%2F1cc1a25b0612b.png&name=1&owner=1&pattern=Circuit%20Board&theme=Dark"></p>

<p id="description">Welcome to AI-Secure Monitor your all-in-one solution for monitoring and securing your PC. Harnessing the power of Artificial Intelligence AI-Secure Monitor offers robust protection against suspicious processes and vulnerabilities in PDFs and image files. With a sleek GUI and transparent operations it ensures that all security operations are conducted locally safeguarding your privacy.</p>

<p align="center"><img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="shields"><img src="https://img.shields.io/badge/Flask-3.0-green" alt="shields"><img src="https://img.shields.io/badge/OpenAI-API-yellow" alt="shields"><img src="https://img.shields.io/badge/Pillow-10.3-orange" alt="shields"><img src="https://img.shields.io/badge/PyMuPDF-1.24.5-red" alt="shields"><img src="https://img.shields.io/badge/License-MIT-brightgreen" alt="shields"></p>

  
 ## Features

Here're some of the project's best features:

- **Monitor Suspicious Processes:** Automatically detect and terminate suspicious processes, logging events and notifying the user.
- **System Log Analysis:** Utilize OpenAI to analyze system logs for potential threats.
- **Alerts and Notifications:** Receive email and GUI notifications for detected threats.
- **Exploit Detection in PDFs and Images:** Upload files for analysis to detect known exploits and threats.
- **User-Friendly GUI:** Interact with the application through a modern and intuitive graphical user interface.
- **Transparent Operations:** All security tasks are performed locally without transmitting data to external servers.

## Requirements

- Python 3
- psutil
- Flask
- requests
- openai
- python-dotenv
- Pillow
- PyMuPDF

## Project Structure 

* AI-Monitor/
* ├── LICENSE
* ├── PRIVACY_POLICY.md
* ├── README.md
* ├── main.py
* ├── email_notifier.py
* ├── assets/
* *    └ largelogo.png
* ├── .env
* └── requirements.txt

  ## Version Released
| Source Code Released | v1.0.0 | Uploading Repository on GitHub                                                                                                        | ✅ |   |
|----------------------|--------|---------------------------------------------------------------------------------------------------------------------------------------|----|---|
| Win10/11 Update      | v1.5.0 | - Added batch script (`run.bat`) to automate setup and launch.  - Added new dialog windows for OpenAI API key and SMTP configuration. | ✅ |   |
| v2.0.0               | v2.0.0 |                                                                🛠️                                                                     | ⚙️ |   |
|                      |        |                                                                                                                                       |    |   |


<h2>🛠️ Installation Steps:</h2>

<p>1. Clone Repository</p>

```
git clone https://github.com/CodeBerserkers888/AI-Secure-Monitor.git cd AI-Secure-Monitor
```

<p>2. Install Requirements</p>

```
pip install -r requirements.txt
```
## Create a .env file and add your OpenAI API key:


OPENAI_API_KEY=your_openai_api_key


## Usage

Run the application with the following command:

```bash
python3 main.py




