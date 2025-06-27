import random
import time


attacks = [
    {"type": "SQL Injection", "payload": "' OR '1'='1"},
    {"type": "XSS", "payload": '<script>alert("XSS")</script>'},
    {"type": "CSRF", "payload": "fake_token"},
]


def simulate_attacks():
    while True:
        attack = random.choice(attacks)
       
        print(f"Attack Type: {attack['type']}, Payload: {attack['payload']}")
        time.sleep(5)  

simulate_attacks()