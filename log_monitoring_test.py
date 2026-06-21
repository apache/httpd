def parse_apache_logs(file_path):
    print(f"Monitoring logs from {file_path} for security anomalies...")

if __name__ == "__main__":
    parse_apache_logs("/var/log/apache2/access.log")