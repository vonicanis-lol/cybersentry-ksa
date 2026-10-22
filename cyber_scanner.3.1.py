import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def get_colors():
  if os.name == "nt":
    os.system("color")
  return {
      "RESET": "\033[0m",
      "GREEN": "\033[92m",
      "RED": "\033[91m",
      "YELLOW": "\033[93m",
      "CYAN": "\033[96m",
      "BOLD": "\033[1m",
  }


C = get_colors()


def print_banner():
  os.system("cls" if os.name == "nt" else "clear")
  print(f"{C['CYAN']}{'=' * 65}{C['RESET']}")
  print(
      f"{C['BOLD']}{C['CYAN']}   CYBERSENTRY KSA v3.1 - Zero-Bug Enterprise Suite"
      f"   {C['RESET']}"
  )
  print(f"{C['CYAN']}{'=' * 65}{C['RESET']}")
  print(f" Location: Jeddah HQ (Acer Aspire)")
  print(
      f" Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
      " UTC"
  )
  print(f"{C['CYAN']}{'=' * 65}{C['RESET']}\n")


def check_ssl_cert(hostname):
  print(f"{C['BOLD']}[+] Checking SSL/TLS Certificate...{C['RESET']}")
  try:
    context = ssl.create_default_context()
    with socket.create_connection((hostname, 443), timeout=4) as sock:
      with context.wrap_socket(sock, server_hostname=hostname) as ssock:
        cert = ssock.getpeercert()
        expire_date_str = cert["notAfter"]
        expire_date = datetime.strptime(expire_date_str, "%b %d %H:%M:%S %Y %Z")
        # Fix: Attach UTC timezone explicitly
        expire_date = expire_date.replace(tzinfo=timezone.utc)
        days_left = (expire_date - datetime.now(timezone.utc)).days

        if days_left > 30:
          print(
              f"  [{C['GREEN']}VALID{C['RESET']}] Certificate active (Expires in"
              f" {C['BOLD']}{days_left}{C['RESET']} days)"
          )
        else:
          print(
              f"  [{C['YELLOW']}WARNING{C['RESET']}] Expiring soon"
              f" ({days_left} days remaining!)"
          )
        return True
  except Exception as e:
    print(f"  [{C['RED']}FAILED{C['RESET']}] SSL/TLS check skipped or failed.")
    return False


def check_headers(url):
  print(f"\n{C['BOLD']}[+] Auditing HTTP Security Headers...{C['RESET']}")
  if not url.startswith("http://") and not url.startswith("https://"):
    url = "https://" + url

  required_headers = {
      "Strict-Transport-Security": "Forces HTTPS (Prevents MitM)",
      "Content-Security-Policy": "Restricts scripts (Prevents XSS)",
      "X-Frame-Options": "Prevents clickjacking",
      "X-Content-Type-Options": "Stops MIME-sniffing",
      "Referrer-Policy": "Controls referrer data",
      "Permissions-Policy": "Restricts hardware/camera access",
  }

  log_buffer = []
  missing_count = 0

  try:
    req = urllib.request.Request(
        url, headers={"User-Agent": "CyberSentryKSA/3.1"}
    )
    with urllib.request.urlopen(req, timeout=5) as response:
      headers = response.info()

      for h, desc in required_headers.items():
        if h in headers:
          print(f"  [{C['GREEN']}PRESENT{C['RESET']}] {h}")
          log_buffer.append(f"[SAFE] {h}: PRESENT")
        else:
          print(
              f"  [{C['RED']}MISSING{C['RESET']}] {h} ->"
              f" {C['YELLOW']}{desc}{C['RESET']}"
          )
          log_buffer.append(f"[RISK] {h}: MISSING ({desc})")
          missing_count += 1

      return missing_count, "\n".join(log_buffer)
  except urllib.error.HTTPError as e:
    print(
        f"  [{C['YELLOW']}NOTE{C['RESET']}] HTTP Response Code {e.code},"
        " analyzing accessible headers..."
    )
    # Even on error codes like 403/404, we can still parse available headers
    headers = e.headers
    for h, desc in required_headers.items():
      if h in headers:
        print(f"  [{C['GREEN']}PRESENT{C['RESET']}] {h}")
        log_buffer.append(f"[SAFE] {h}: PRESENT")
      else:
        print(
            f"  [{C['RED']}MISSING{C['RESET']}] {h} ->"
            f" {C['YELLOW']}{desc}{C['RESET']}"
        )
        log_buffer.append(f"[RISK] {h}: MISSING ({desc})")
        missing_count += 1
    return missing_count, "\n".join(log_buffer)
  except Exception as e:
    print(f"  [{C['RED']}!] Header Audit Error:{C['RESET']} Connection timeout")
    return len(required_headers), "Audit Failed due to timeout"


def check_open_ports(hostname):
  print(f"\n{C['BOLD']}[+] Auditing Critical Ports...{C['RESET']}")
  ports = {
      21: "FTP (File Transfer)",
      22: "SSH (Admin Access)",
      80: "HTTP (Unencrypted)",
      443: "HTTPS (Secure Web)",
      3306: "MySQL (Database)",
  }

  ftp_exposed = False
  try:
    ip = socket.gethostbyname(hostname)
    print(f"  Target IP Address: {C['CYAN']}{ip}{C['RESET']}")
  except socket.gaierror:
    print(f"  [{C['RED']}!{C['RESET']}] Could not resolve hostname IP.")
    return False

  for port, service in ports.items():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.6)
    try:
      res = s.connect_ex((ip, port))
      if res == 0:
        print(f"  [{C['RED']}OPEN{C['RESET']}] Port {port:4d} - {service}")
        if port == 21:
          ftp_exposed = True
      else:
        print(f"  [{C['GREEN']}CLOSED{C['RESET']}] Port {port:4d} - {service}")
    except Exception:
      print(f"  [{C['YELLOW']}FILTERED{C['RESET']}] Port {port:4d} - {service}")
    s.close()

  if ftp_exposed:
    print(
        f"\n  {C['RED']}{C['BOLD']}[!] ALERT: PORT 21 (FTP) IS OPEN TO PUBLIC"
        f" INTERNET!{C['RESET']}"
    )

  return ftp_exposed


def calculate_grade(missing_count):
  if missing_count == 0:
    return f"{C['GREEN']}{C['BOLD']}A+ (PERFECT HARDENING){C['RESET']}"
  elif missing_count == 1:
    return f"{C['GREEN']}A (MINOR EXPOSURE){C['RESET']}"
  elif missing_count == 2:
    return f"{C['YELLOW']}B (MODERATE VULNERABILITY){C['RESET']}"
  elif missing_count == 3:
    return f"{C['YELLOW']}C (ACTION RECOMMENDED){C['RESET']}"
  else:
    return f"{C['RED']}{C['BOLD']}F (HIGH RISK EXPOSURE){C['RESET']}"


def save_report_to_file(target, grade_str, present_count, missing_count, log_data):
  filename = f"report_{target.replace('.', '_')}.txt"
  try:
    with open(filename, "w", encoding="utf-8") as f:
      f.write("=" * 65 + "\n")
      f.write(f" CYBERSENTRY KSA - AUDIT REPORT: {target}\n")
      f.write(
          f" Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC\n"
      )
      f.write("=" * 65 + "\n\n")
      f.write(log_data + "\n\n")
      f.write(f"Headers Present: {present_count} / 6\n")
      f.write(f"Headers Missing: {missing_count} / 6\n")
      f.write(f"Security Grade: {grade_str}\n")
      f.write("=" * 65 + "\n")
    print(
        f"\n{C['CYAN']}[+] Report successfully generated locally as:"
        f" {C['BOLD']}{filename}{C['RESET']}"
    )
  except Exception as e:
    print(f"{C['RED']}Could not save text report file: {e}{C['RESET']}")


def main():
  while True:
    print_banner()
    print("Select Target Preset:")
    print("  [1] canva.com")
    print("  [2] salla.com")
    print("  [3] nvidia.com")
    print("  [4] Custom Domain")
    print("  [5] Exit Suite")

    choice = input(
        f"\n{C['BOLD']}Enter option (1-5): {C['RESET']}"
    ).strip()

    targets = {
        "1": "canva.com",
        "2": "salla.com",
        "3": "nvidia.com",
    }

    if choice in targets:
      target = targets[choice]
    elif choice == "4":
      target = input(
          f"{C['BOLD']}Enter custom domain (e.g., example.com): {C['RESET']}"
      ).strip()
    elif choice == "5":
      print(f"\n{C['CYAN']}Exiting CyberSentry KSA. Stay secure!{C['RESET']}")
      sys.exit()
    else:
      print(f"\n{C['RED']}Invalid option. Please choose between 1 and 5.{C['RESET']}")
      input(f"\n{C['BOLD']}Press Enter to continue...{C['RESET']}")
      continue

    if not target:
      continue

    clean_host = (
        target.replace("https://", "").replace("http://", "").split("/")[0]
    )

    print(
        f"\n{C['BOLD']}Initializing Audit for:"
        f" {C['CYAN']}{clean_host}{C['RESET']}{C['BOLD']}...{C['RESET']}"
    )
    print("-" * 55)

    check_ssl_cert(clean_host)
    missing_count, log_data = check_headers(clean_host)
    check_open_ports(clean_host)

    grade = calculate_grade(missing_count)
    present_count = 6 - missing_count

    print(f"\n{C['CYAN']}{'=' * 65}{C['RESET']}")
    print(f"                      {C['BOLD']}EXECUTIVE SUMMARY{C['RESET']}                    ")
    print(f"{C['CYAN']}{'=' * 65}{C['RESET']}")
    print(f" Security Grade: {grade}")
    print(f" Headers Present: {present_count} / 6")
    print(f" Headers Missing: {missing_count} / 6")
    print(f"{C['CYAN']}{'=' * 65}{C['RESET']}")

    save_report_to_file(
        clean_host, grade, present_count, missing_count, log_data
    )

    cont = input(
        f"\n{C['BOLD']}Run another scan? (y/n): {C['RESET']}"
    ).strip().lower()
    if cont != "y":
      print(
          f"\n{C['CYAN']}Shutting down Jeddah mobile command center. Goodbye!{C['RESET']}"
      )
      break


if __name__ == "__main__":
  main()