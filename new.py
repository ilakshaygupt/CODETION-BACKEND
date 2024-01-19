import requests

url = 'http://127.0.0.1:8000/api/password-reset/'
headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
    'X-CSRFToken': 'NtVbnX14gYwuPLaTw9qyoizyyNLoT0tgHFPHwZWMQu6xjdoo3pwX8N0KMC5AY4nm'
}
data = {
    'email': 'iamlakshay04@gmail.com'
}

response = requests.post(url, headers=headers, json=data)
print(response)