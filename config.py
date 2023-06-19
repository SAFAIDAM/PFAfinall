from dotenv import load_dotenv
import os
FLASK_DEBUG = os.getenv('FLASK_DEBUG')
FLASK_APP = os.getenv('FLASK_APP')
load_dotenv()
