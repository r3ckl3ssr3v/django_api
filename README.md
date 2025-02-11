# Launching a Web Application on Localhost

This guide provides step-by-step instructions for setting up and launching your web application on your local machine.

## Prerequisites

Before starting, ensure you have the following tools installed on your system:

- **Python 3.x** (Preferably Python 3.8 or above)
- **Django** (or any other web framework you're using)
- **Virtual Environment** (for managing dependencies)
- **Ngrok** (if needed for external access via a tunneling service)
- **Text Editor or IDE** (e.g., Visual Studio Code, PyCharm, etc.)

## Steps to Launch the Web Application Locally

### 1. Clone the Repository

Begin by cloning the repository to your local machine. If you have a GitHub repository, use the following command:

- git clone [https://github.com/your-username/your-repository-name.git](https://github.com/r3ckl3ssr3v/django_api.git)
- cd your-repository-name

### 2. Set Up a Virtual Environment
A virtual environment is recommended to isolate your project dependencies.

For Windows:
- python -m venv venv
- .\venv\Scripts\activate

For macOS/Linux:
- python3 -m venv venv
- source venv/bin/activate

### 3. Install Project Dependencies
Next, install all required dependencies listed in the requirements.txt file:
- pip install -r requirements.txt

### 4. Set Up Configuration
Ensure you have the correct settings in place. This might include API keys, database settings, or any other configuration variables. These are typically located in a settings or configuration file, such as settings.py for Django.

Example Configuration (Django):
In settings.py, ensure that the ALLOWED_HOSTS include your local server address (127.0.0.1 or localhost):

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

### 5. Run Database Migrations (if applicable)
If your project uses a database (such as SQLite, PostgreSQL, etc.), run the following command to set up the database schema:

- python manage.py migrate
  
This command applies the necessary database migrations to ensure everything is set up correctly.

### 6. Launch the Web Server
Now, you can start the Django development server (or the relevant server for your framework):

- python manage.py runserver
- This will start the development server at http://127.0.0.1:8000/.

If using Django, the default address will be http://127.0.0.1:8000/.
If using other frameworks, refer to their respective commands for starting the local server.

### 7. Access the Application
Open your web browser and navigate to the following URL:

- http://127.0.0.1:8000/
  
This will load the homepage of your web application running locally.

### 8. Expose Localhost Externally Using Ngrok
If you want to expose your local development environment to the outside world (e.g., for testing with APIs or sharing with others), you can use Ngrok.

Download and install Ngrok.
Start Ngrok with the following command to tunnel the local server:

- ngrok http 127.0.0.1:8000
  
Ngrok will provide a public URL (e.g., https://abcd-1234.ngrok.io) that you can use to access your local server externally.

### 9. Create an app in the https://smartapi.angelbroking.com/create and paste the ngrok link in the Redirect URL there.
- Add ngrok URL to CSRF_TRUSTED_ORIGINS in settings.py.
- Modify settings.py
- Add the API credentials you received from Angel Broking to your settings.py file

  - ANGEL_API_KEY = "your_api_key_here"
  - ANGEL_API_SECRET = "your_api_secret_here"
  - ANGEL_REDIRECT_URI = "[http://127.0.0.1:8000/angel_callback/](https://smartapi.angelone.in/publisher-login?api_key=xxx&state=statevariable)"
