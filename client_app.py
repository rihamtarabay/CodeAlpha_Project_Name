import requests

def upload_file(file_path, username):
    url = "http://localhost:5000/upload"
    files = {'file': open(file_path, 'rb')}
    data = {'username': username}
    response = requests.post(url, files=files, data=data)
    print(response.json())

# Example usage
# upload_file("example.txt.enc", "testuser")
