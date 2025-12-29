import json
import os
import datetime

class BehaviorLogger:
    def __init__(self, log_dir):
        self.log_dir = log_dir
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
            
        self.normal_log = os.path.join(self.log_dir, 'normal_activity.log')
        self.suspicious_log = os.path.join(self.log_dir, 'suspicious_activity.log')
        self.malicious_log = os.path.join(self.log_dir, 'malicious_alerts.log')

    def log_event(self, level, session_id, data):
        """
        level: 0-3 (0: Benign, 1: Low, 2: Medium/Suspicious, 3: High/Malicious)
        """
        timestamp = datetime.datetime.now().isoformat()
        
        entry = {
            "timestamp": timestamp,
            "session_id": session_id,
            "level": level,
        }
        
        # Add classification based on level
        if level >= 3:
            classification = "MALICIOUS"
            target_file = self.malicious_log
            # Full detail for malicious
            entry["event"] = "ALERT"
            entry["intelligence"] = data
            entry["explanation"] = data.get('summary', 'N/A')
        elif level == 2:
            classification = "SUSPICIOUS"
            target_file = self.suspicious_log
            # Detailed command logs for suspicious
            entry["event"] = "DETECTION"
            entry["commands"] = data.get('commands', [])
            entry["intent"] = data.get('intent', 'Unknown')
            entry["explanation"] = data.get('summary', 'N/A')
        else:
            classification = "NORMAL"
            target_file = self.normal_log
            # Minimal logs for normal but with explanation
            entry["event"] = "INFO"
            entry["explanation"] = data.get('summary', 'Normal activity detected')

        entry["classification"] = classification

        with open(target_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
            
        print(f"[*] Logged {classification} event for session {session_id} to {os.path.basename(target_file)}")

if __name__ == "__main__":
    # Test
    logger = BehaviorLogger('./logs_test')
    logger.log_event(1, "test-sid-1", {})
    logger.log_event(2, "test-sid-2", {"commands": ["ls", "sudo"], "intent": "Privilege Escalation"})
    logger.log_event(3, "test-sid-3", {"all_info": "significant malicious behavior"})
