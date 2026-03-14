from datetime import datetime
import json

class ZPAPolicyEngine:
    def __init__(self):
        # Mock Azure Active Directory Users and Groups
        self.directory = {
            "alice": {"group": "Finance_ERP_Users"},
            "bob": {"group": "Project_X_Contractors"},
            "charlie": {"group": "Executive_Board"},
            "dave": {"group": "Linux_Admins"},
            "eve": {"group": "Windows_Admins"}
        }

        # Defined Application Segments
        self.applications = [
            "ERP System",
            "Git Repository",
            "File Server",
            "Linux Server (SSH)",
            "Windows Server (RDP)"
        ]

    def _evaluate_identity(self, username, expected_group):
        user = self.directory.get(username)
        if not user:
            return False, f"User '{username}' not found in Directory."
        if user["group"] != expected_group:
            return False, f"User '{username}' is not in '{expected_group}'."
        return True, "Identity verified."

    def _evaluate_device_posture(self, device_posture, requirements):
        for req in requirements:
            if not device_posture.get(req, False):
                return False, f"Device posture failed: Missing '{req}'."
        return True, "Device posture verified."

    def _evaluate_time(self, current_time, allowed_range):
        if not allowed_range:
            return True, "No time restrictions."
        
        start_hour, end_hour = allowed_range
        # Simplified time check (ignoring minutes/timezone for demo)
        hour = min(current_time.hour, 23)
        if start_hour <= hour < end_hour:
            return True, "Time within allowed range."
        return False, f"Access outside permitted hours ({start_hour}:00 - {end_hour}:00)."

    def evaluate_request(self, username, requested_app, context):
        """
        Evaluates an access request based on Zero Trust principles.
        """
        print(f"\n[ZPA Broker] Receiving connection request from '{username}' to '{requested_app}'...")
        print(f"[ZPA Broker] Context: {json.dumps(context, default=str)}")

        if requested_app not in self.applications:
            return {"status": "DENY", "reason": f"Application '{requested_app}' is not a defined segment."}

        # Policy sets based on application
        if requested_app == "ERP System":
            id_ok, msg = self._evaluate_identity(username, "Finance_ERP_Users")
            if not id_ok: return {"status": "DENY", "reason": msg}
            
            if not context.get("mfa_verified", False):
                return {"status": "DENY", "reason": "MFA verification required."}
                
            posture_ok, msg = self._evaluate_device_posture(context.get("device", {}), ["company_laptop", "antivirus"])
            if not posture_ok: return {"status": "DENY", "reason": msg}
            
            return {"status": "ALLOW", "tunnel": f"Micro-tunnel assigned: {username} <---> ERP System (TLS 1.3)"}

        elif requested_app == "Git Repository":
            id_ok, msg = self._evaluate_identity(username, "Project_X_Contractors")
            if not id_ok: return {"status": "DENY", "reason": msg}
            
            time_ok, msg = self._evaluate_time(context.get("time", datetime.now()), (9, 17)) # 9 AM to 5 PM
            if not time_ok: return {"status": "DENY", "reason": msg}
            
            return {"status": "ALLOW", "tunnel": f"Micro-tunnel assigned: {username} <---> Git Server (TLS 1.3)"}

        elif requested_app == "File Server":
            # Explicit deny for contractors, allow for internal users (simplified)
            user = self.directory.get(username)
            if user and user["group"] == "Project_X_Contractors":
                return {"status": "DENY", "reason": "Contractors are prohibited from accessing File Servers."}
            return {"status": "DENY", "reason": "Default Deny: No explicit policy granting access."}
            
        elif requested_app == "Confidential Board Documents":
            # Simulated edge case for executives (not in original app list but in scenario)
            pass

        return {"status": "DENY", "reason": "Default implicit deny."}

    def evaluate_executive_request(self, username, context):
        """Scenario 3 explicit method"""
        print(f"\n[ZPA Broker] Receiving connection request from '{username}' to 'Confidential Board Documents'...")
        id_ok, msg = self._evaluate_identity(username, "Executive_Board")
        if not id_ok: return {"status": "DENY", "reason": msg}
        
        posture_ok, msg = self._evaluate_device_posture(context.get("device", {}), ["mdm_verified", "encryption"])
        if not posture_ok: return {"status": "DENY", "reason": msg}
        
        if context.get("location") != "trusted":
             return {"status": "DENY", "reason": "Access denied from untrusted location."}
             
        return {"status": "ALLOW", "tunnel": f"Micro-tunnel assigned: {username} <---> Confidential Board Documents (TLS 1.3)"}

    def evaluate_admin_request(self, username, server_type):
         """Scenario 4 explicit method"""
         print(f"\n[ZPA Broker] Receiving Admin connection request from '{username}' to '{server_type}'...")
         if server_type == "Linux Server (SSH)":
             id_ok, msg = self._evaluate_identity(username, "Linux_Admins")
         elif server_type == "Windows Server (RDP)":
             id_ok, msg = self._evaluate_identity(username, "Windows_Admins")
         else:
             return {"status": "DENY", "reason": "Unknown server type."}
             
         if not id_ok: return {"status": "DENY", "reason": msg}
         
         return {
             "status": "ALLOW", 
             "tunnel": f"Secure application-level connection: {username} <---> {server_type}",
             "note": "Admin has NO network-level access, only application-level."
         }
