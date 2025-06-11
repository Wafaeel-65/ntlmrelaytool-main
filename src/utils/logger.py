class Logger:
    def __init__(self, log_file='app.log'):
        self.log_file = log_file

    def log_info(self, message):
        with open(self.log_file, 'a') as f:
            f.write(f'INFO: {message}\n')

    def log_error(self, message):
        with open(self.log_file, 'a') as f:
            f.write(f'ERROR: {message}\n')