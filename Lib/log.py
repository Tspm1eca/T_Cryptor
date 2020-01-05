import logging

class Logger(object):
    def __init__(self, logger_name='MyLog'):

        self.logger = logging.getLogger(logger_name)
        logging.root.setLevel(logging.NOTSET)


    def get_logger(self, level=logging.DEBUG, formatter=\
                   logging.Formatter("[%(levelname)s] [%(lineno)d] %(funcName)s : %(message)s")):
        if not self.logger.handlers:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(level)
            self.logger.addHandler(console_handler)

        return self.logger

level = {"CRITICAL" : logging.CRITICAL,
"ERROR" : logging.ERROR,
"WARNING" : logging.WARNING,
"INFO" : logging.INFO,
"DEBUG" : logging.DEBUG,
"NOTSET" : logging.NOTSET}

# ??
# logger = log.Logger().get_logger(level = log.level["WARNING"])
