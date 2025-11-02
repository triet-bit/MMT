import json
import datetime

MSG_TYPE_REGISTER = "REGISTER"      # Peer registration
MSG_TYPE_TEXT = "TEXT"              # Text message
MSG_TYPE_BROADCAST = "BROADCAST"    # Broadcast to all peers
MSG_TYPE_DIRECT = "DIRECT"          # Direct message to specific peer
MSG_TYPE_JOIN_CHANNEL = "JOIN_CHANNEL"   # Join a channel
MSG_TYPE_LEAVE_CHANNEL = "LEAVE_CHANNEL" # Leave a channel
MSG_TYPE_CHANNEL_MSG = "CHANNEL_MSG"     # Message in a channel
MSG_TYPE_PEER_LIST = "PEER_LIST"    # Request peer list
MSG_TYPE_HEARTBEAT = "HEARTBEAT"    # Keep-alive ping
MSG_TYPE_ACK = "ACK"                # Acknowledgment

class P2PMessage: #standardize for all message
    def __init__(self, msg_type, sender_id, data=None):

        self.type = msg_type
        self.sender = sender_id
        self.timestamp = datetime.datetime.now().isoformat()
        self.data = data or {}
    def to_json(self): # convert message to json string
        message = {
            "type": self.type, 
            "sender": self.sender, 
            "timestamp": self.timestamp, 
            "data": self.data
        }
        return json.dump(message)
    def to_bytes(self):
        self.to_json().encode('utf-8')
    @staticmethod
    def from_json(json_str): # str->json
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            print(f"[Protocol] Error parsing JSON: {e}")
            return None
    @staticmethod
    def from_bytes(data):
        try: 
            json_str = data.decode('utf-8')
            return P2PMessage.from_json(json_str)
        except Exception as e: 
            print(f"[Protocol] Error parsing bytes: {e}")
            return None

class MessageFactory: 
    @staticmethod
    def create_register_message(peer_id, ip, port):
        """
        Create peer registration message.
        """
        data = {
            "peer_id": peer_id,
            "ip": ip,
            "port": port
        }
        return P2PMessage(MSG_TYPE_REGISTER, peer_id, data)
    
    @staticmethod
    def create_text_message(sender_id, text, recipient=None):
        """
        Create text message (direct or broadcast).
        """
        msg_type = MSG_TYPE_DIRECT if recipient else MSG_TYPE_BROADCAST
        data = {
            "text": text,
            "recipient": recipient
        }
        return P2PMessage(msg_type, sender_id, data)
    
    @staticmethod
    def create_channel_message(sender_id, channel_name, text):
        """
        Create channel message.
        """
        data = {
            "channel": channel_name,
            "text": text
        }
        return P2PMessage(MSG_TYPE_CHANNEL_MSG, sender_id, data)
    
    @staticmethod
    def create_join_channel_message(peer_id, channel_name):
        """
        Create join channel message.
        """
        data = {
            "channel": channel_name
        }
        return P2PMessage(MSG_TYPE_JOIN_CHANNEL, peer_id, data)
    
    @staticmethod
    def create_heartbeat_message(peer_id):
        """
        Create heartbeat/keep-alive message.
        """
        return P2PMessage(MSG_TYPE_HEARTBEAT, peer_id, {})
    
    @staticmethod
    def create_ack_message(peer_id, ack_for):
        """
        Create acknowledgment message.
        """
        data = {
            "ack_for": ack_for
        }
        return P2PMessage(MSG_TYPE_ACK, peer_id, data)
