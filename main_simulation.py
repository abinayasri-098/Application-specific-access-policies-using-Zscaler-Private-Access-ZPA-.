from zpa_policy_engine import ZPAPolicyEngine
from vulnerability_scanner import VulnerabilityScanner
from datetime import datetime

def run_simulation():
    engine = ZPAPolicyEngine()

    print("==================================================")
    print(" ZERO TRUST ARCHITECTURE & VULNERABILITY SIMULATION")
    print("==================================================")

    # Scenario 1 – Finance ERP Access
    print("\n\n--- SCENARIO 1: Finance ERP Access ---")
    context_s1 = {
        "mfa_verified": True,
        "device": {"company_laptop": True, "antivirus": True}
    }
    result = engine.evaluate_request("alice", "ERP System", context_s1)
    print(f"Result: {result['status']}")
    if result['status'] == 'ALLOW':
        print(f"Tunnel: {result['tunnel']}")
    else:
        print(f"Reason: {result['reason']}")

    # Scenario 2 – Contractor Repository Access
    print("\n\n--- SCENARIO 2: Contractor Repository Access ---")
    context_s2 = {
        "time": datetime(2025, 10, 24, 14, 0) # 2:00 PM
    }
    # Test valid access
    result1 = engine.evaluate_request("bob", "Git Repository", context_s2)
    print(f"\nRequest 1 (Git Server): {result1['status']}")
    if result1['status'] == 'ALLOW': print(f"Tunnel: {result1['tunnel']}")
    
    # Test invalid access (Lateral movement prevention)
    result2 = engine.evaluate_request("bob", "File Server", context_s2)
    print(f"\nRequest 2 (File Server): {result2['status']}")
    if result2['status'] == 'DENY': print(f"Reason: {result2['reason']}")

    # Scenario 3 – Executive Document Access
    print("\n\n--- SCENARIO 3: Executive Document Access ---")
    context_s3 = {
        "device": {"mdm_verified": True, "encryption": True},
        "location": "trusted"
    }
    result = engine.evaluate_executive_request("charlie", context_s3)
    print(f"Result: {result['status']}")
    if result['status'] == 'ALLOW':
        print(f"Tunnel: {result['tunnel']}")
    else:
        print(f"Reason: {result['reason']}")

    # Scenario 4 – Administrator Server Access
    print("\n\n--- SCENARIO 4: Administrator Server Access ---")
    result = engine.evaluate_admin_request("dave", "Linux Server (SSH)")
    print(f"Result: {result['status']}")
    if result['status'] == 'ALLOW':
        print(f"Tunnel: {result['tunnel']}")
        print(f"Note: {result.get('note')}")

    # Vulnerability Assessment Module
    print("\n\n--- SCENARIO 5: Vulnerability Assessment ---")
    scanner = VulnerabilityScanner("http://testfire.net")
    scanner.run_scan()
    scanner.demonstrate_xss()
    scanner.show_mitigations()

    print("\n\n==================================================")
    print(" SIMULATION COMPLETE")
    print("==================================================")

if __name__ == "__main__":
    run_simulation()
