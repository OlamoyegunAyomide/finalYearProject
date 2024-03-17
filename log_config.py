import logging
#Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

#Create a file handler and set its log level
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)

#Creata a formatter and add it to the file handler
formatter = logging.Formatter('%(asctime)s - %(levelname)s-%(message)s')
file_handler.setFormatter(formatter)

#Add the file handler to the logger
logger.addHandler(file_handler)