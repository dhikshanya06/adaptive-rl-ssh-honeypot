import json
import os

class SessionAnalyzer:
    def __init__(self, log_path="/home/dhikshanya06/cowrie/var/log/cowrie/cowrie.json"):
        self.log_path = log_path

    def parse_logs(self):
        if not os.path.exists(self.log_path):
            return {}

        sessions = {}
        with open(self.log_path, 'r') as f:
            for line in f:
                try:
                    event = json.loads(line)
                    session_id = event.get('session')
                    if not session_id:
                        continue
                    
                    if session_id not in sessions:
                        sessions[session_id] = []
                    sessions[session_id].append(event)
                except json.JSONDecodeError:
                    continue
        return sessions

    def get_latest_session(self):
        sessions = self.parse_logs()

        if not sessions:
            return None

        # Return the most recently updated session based on the timestamp of the last event
        latest_session_id = max(sessions.keys(), key=lambda s: sessions[s][-1].get('timestamp', ''))
        return {
            'session_id': latest_session_id,
            'events': sessions[latest_session_id]
        }

    def summarize_session(self, session_data):
        if not session_data:
            return None

        summary = {
            'session_id': session_data['session_id'],
            'start_time': session_data['events'][0].get('timestamp'),
            'end_time': session_data['events'][-1].get('timestamp'),
            'commands': [],
            'login_attempts': [],
            'src_ip': None
        }

        for event in session_data['events']:
        #source-ip extraction
            if not summary['src_ip'] and event.get('src_ip'):
                summary['src_ip'] = event.get('src_ip')
        #command extraction
            if event.get('eventid') == 'cowrie.command.input':
                summary['commands'].append(event.get('input'))
        #login success tracking
            elif event.get('eventid') == 'cowrie.login.success':
                summary['login_attempts'].append({'username': event.get('username'), 'password': event.get('password'), 'success': True})
            elif event.get('eventid') == 'cowrie.login.failed':
                summary['login_attempts'].append({'username': event.get('username'), 'password': event.get('password'), 'success': False})

        return summary

if __name__ == "__main__":
    analyzer = SessionAnalyzer()
    latest = analyzer.get_latest_session()
    if latest:
        summary = analyzer.summarize_session(latest)
        
        # Calculate duration
        try:
            from datetime import datetime
            start = datetime.fromisoformat(summary['start_time'].rstrip('Z'))
            end = datetime.fromisoformat(summary['end_time'].rstrip('Z'))
            duration = int((end - start).total_seconds())
        except Exception:
            duration = "Unknown"

        print("\nSESSION FACTS (LATEST SESSION ONLY)")
        print("-" * 35)
        print(f"Session ID      : {summary['session_id']}")
        print(f"Source IP       : {summary['src_ip']}")
        print(f"Commands        : {summary['commands']}")
        print(f"Duration (sec)  : {duration}\n")
    else:
        print("No sessions found.")
