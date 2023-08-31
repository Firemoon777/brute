import subprocess


class Honeypot:
    def start(self):
        ...

    def stop(self):
        ...

    def get_ip(self):
        ...


class DockerHoneypot(Honeypot):
    def __init__(self, image=None):
        self.image = image or "honeypot:latest"
        self.container_id = None

    def start(self):
        self.container_id = subprocess.check_output(["docker", "run", "-d", self.image]).decode().strip()

    def get_ip(self):
        ip = subprocess.check_output([
            "docker",
            "inspect",
            "-f",
            "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            self.container_id
        ])
        return ip.decode().strip()

    def stop(self):
        subprocess.check_call(["docker", "kill", self.container_id])