# The file Dockerfile defines the image's environment
# Import Python runtime and set up working directory
# This specified runtime has known vulnerabilities so that vulnerability
# scanning can be tested.
FROM python:3.5-slim
WORKDIR /app
ADD . /app

# Install any necessary dependencies
RUN pip install -r requirements.txt

# Open port 80 for serving the webpage
EXPOSE 80

# Run app.py when the container launches
CMD ["python", "app.py"]
