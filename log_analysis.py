import re
import csv
from collections import defaultdict

# Function to parse and analyze the log file in one pass
def analyze_log_file(log_file, threshold=3):  # Lowered threshold to 3
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_attempts = defaultdict(int)

    # Process the file line by line
    try:
        with open(log_file, 'r') as file:
            for line in file:
                # Debug: Print each line being processed
                print(f"Processing line: {line.strip()}")

                # Extract IP address (Ensure we're capturing the correct format)
                ip_match = re.match(r'^(\d+\.\d+\.\d+\.\d+)', line)
                ip = ip_match.group(1) if ip_match else None
                print(f"IP Address: {ip}")  # Debug output

                # Extract endpoint (Make sure this correctly matches all types of requests)
                endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE)\s+([^\s]+)', line)
                endpoint = endpoint_match.group(1) if endpoint_match else None
                print(f"Endpoint: {endpoint}")  # Debug output

                # Extract status code (Ensuring we're capturing 3-digit codes)
                status_match = re.search(r'" (\d{3})', line)
                status_code = int(status_match.group(1)) if status_match else None
                print(f"Status Code: {status_code}")  # Debug output

                # Count requests per IP
                if ip:
                    ip_counts[ip] += 1

                # Count endpoint accesses
                if endpoint:
                    endpoint_counts[endpoint] += 1

                # Track failed login attempts (consider both status code 401 and custom failure message)
                if status_code == 401 or 'Invalid credentials' in line:
                    if ip:
                        failed_attempts[ip] += 1

        # Debugging: Print failed login attempts for each IP
        print("\nFailed login attempts per IP:")
        for ip, count in failed_attempts.items():
            print(f"{ip}: {count}")

        # Identify most accessed endpoint
        most_accessed_endpoint = max(endpoint_counts.items(), key=lambda x: x[1], default=("None", 0))

        # Filter suspicious activities based on threshold
        suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count >= threshold}

        return ip_counts, most_accessed_endpoint, suspicious_ips

    except FileNotFoundError:
        print(f"Error: Log file '{log_file}' not found.")
        return {}, ("None", 0), {}
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return {}, ("None", 0), {}

# Function to write results to CSV
def write_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips):
    try:
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)

            # Write IP request counts
            writer.writerow(["IP Address", "Request Count"])
            for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])

            # Write most accessed endpoint
            writer.writerow([])
            writer.writerow(["Most Frequently Accessed Endpoint"])
            writer.writerow(["Endpoint", "Access Count"])
            writer.writerow(most_accessed_endpoint)

            # Write suspicious activity
            writer.writerow([])
            writer.writerow(["Suspicious Activity Detected"])
            writer.writerow(["IP Address", "Failed Login Count"])
            for ip, count in suspicious_ips.items():
                writer.writerow([ip, count])

        print(f"\nResults saved to {output_file}")

    except Exception as e:
        print(f"An error occurred while writing to the file: {e}")

# Main function
def main():
    log_file = "sample.log"  # Input log file
    output_file = "log_analysis_results.csv"  # Output CSV file
    threshold = 3  # Reduced failed login attempt threshold to 3

    # Analyze log file
    ip_counts, most_accessed_endpoint, suspicious_ips = analyze_log_file(log_file, threshold)

    if not ip_counts and most_accessed_endpoint == ("None", 0) and not suspicious_ips:
        print("No data to display or write. Exiting.")
        return

    # Display results in terminal
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Write results to CSV
    write_to_csv(output_file, ip_counts, most_accessed_endpoint, suspicious_ips)

# Run the main function
if __name__ == "__main__":
    main()
