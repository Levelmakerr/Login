import os
from dotenv import load_dotenv

# Load environment variables from the .env file
load_dotenv()

EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_HOST_USER = 'vishnutest33@gmail.com'
EMAIL_HOST_PASSWORD = os.getenv('ijef sioq tihe atvx')
EMAIL_PORT = 587