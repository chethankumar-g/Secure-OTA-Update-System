import logging

# Flask logging configuration
flask_logger = logging.getLogger('werkzeug')  # Flask uses Werkzeug for logging
flask_handler = logging.FileHandler('flask_requests.log')  # Log Flask-specific logs
flask_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
flask_handler.setFormatter(flask_formatter)
flask_logger.addHandler(flask_handler)
flask_logger.setLevel(logging.INFO)

# Program-specific logging configuration
program_logger = logging.getLogger('program_logger')
program_handler = logging.FileHandler('program_operations.log')  # Log program-specific logs
program_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
program_handler.setFormatter(program_formatter)
program_logger.addHandler(program_handler)
program_logger.setLevel(logging.INFO)

