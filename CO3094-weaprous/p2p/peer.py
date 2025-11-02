import socket
import threading
import json
import time
from datetime import datetime

from p2p.p2p_protocol import P2PMessage, MessageFactory
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

class ChatPeer: 
    """
    Each can: 
        - accept connections form others
        - connect to other peers
        - send/receive messages
        - manage channels
    """
    def __init__(self, peer_id, listen_ip="0.0.0.0", listen_port=5000):
        """
        peer_id (str): Unique identifier for this peer
        listen_ip (str): IP address to bind listening socket
        listen_port (int): Port to listen on for incoming connections
        """
        self.peer_id = peer_id
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.server_socket = None
        self.peer_connections = {} #{peer_id: socket}
        self.peer_list = {} # {peer_id: (ip, port)}
        self.channels = {} # {channel_name: [peer_ids]}
        self.message_history = [] # [(timestamp, sender, message)]
        self.running = False
        self.lock = threading.Lock()
        
        print(f"[Peer {self.peer_id}] Initialized")
    def start(self): 
        try: 
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.listen_ip, self.listen_port))
            self.server_socket.listen(10)
            self.running = True
            print(f"[Peer {self.peer_id}] Listening on {self.listen_ip}:{self.listen_port}")
            
            accept_thread = threading.Thread(target=self._accept_connections, daemon=True)
            accept_thread.start()
        except Exception as e: 
            print(f"[Peer {self.peer_id}] Error starting: {e}")
            self.running = False
    
    def _accept_connections(self):
        """
        Accept incoming peer connections (runs in separate thread).
        """
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                print(f"[Peer {self.peer_id}] New connection from {addr}")
                
                # Spawn thread to handle this peer connection
                handler_thread = threading.Thread(
                    target=self._handle_peer_connection,
                    args=(conn, addr),
                    daemon=True
                )
                handler_thread.start()
                
            except Exception as e:
                if self.running:
                    print(f"[Peer {self.peer_id}] Error accepting connection: {e}")
    
      
    def _handle_peer_connection(self, conn, addr):
        """
        Handle messages from a connected peer.
        
        :param conn (socket): Peer connection socket
        :param addr (tuple): Peer address (ip, port)
        """
        peer_id = None
        
        try:
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break
                
                message = P2PMessage.from_bytes(data)
                if not message:
                    continue
                
                sender_id = message.get('sender')
                msg_type = message.get('type')
                msg_data = message.get('data', {})
                
                if sender_id and sender_id not in self.peer_connections:
                    with self.lock:
                        self.peer_connections[sender_id] = conn
                        peer_id = sender_id
                    print(f"[Peer {self.peer_id}] Registered connection from {sender_id}")
                
                self._process_message(message)
                
        except Exception as e:
            print(f"[Peer {self.peer_id}] Error handling peer {addr}: {e}")
        finally:
            if peer_id:
                with self.lock:
                    if peer_id in self.peer_connections:
                        del self.peer_connections[peer_id]
                print(f"[Peer {self.peer_id}] Disconnected from {peer_id}")
            conn.close()
    def _process_message(self, message):
        """
        Process received message based on type
        """
        if not message:
            return
        
        msg_type = message.get('type')
        sender = message.get('sender')
        data = message.get('data', {})
        timestamp = message.get('timestamp')
        
        with self.lock:
            self.message_history.append((timestamp, sender, message))
        
        # Handle different message types
        if msg_type == MSG_TYPE_TEXT:
            text = data.get('text', '')
            print(f"\n[{timestamp}] {sender}: {text}")
        
        elif msg_type == MSG_TYPE_BROADCAST:
            text = data.get('text', '')
            print(f"\n[BROADCAST] [{timestamp}] {sender}: {text}")
        
        elif msg_type == MSG_TYPE_CHANNEL_MSG:
            channel = data.get('channel', 'unknown')
            text = data.get('text', '')
            print(f"\n[#{channel}] [{timestamp}] {sender}: {text}")
    def connect_to_peer(self, peer_id, peer_ip, peer_port):
        """
        Connect to another peer.
        
        :param peer_id (str): Target peer ID
        :param peer_ip (str): Target peer IP address
        :param peer_port (int): Target peer port
        :rtype bool: True if connection successful
        """
        try:
            # Check if already connected
            if peer_id in self.peer_connections:
                print(f"[Peer {self.peer_id}] Already connected to {peer_id}")
                return True
            
            # Create connection
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((peer_ip, peer_port))
            
            # Store connection
            with self.lock:
                self.peer_connections[peer_id] = peer_socket
                self.peer_list[peer_id] = (peer_ip, peer_port)
            
            print(f"[Peer {self.peer_id}] Connected to {peer_id} at {peer_ip}:{peer_port}")
            
            # Send registration message
            register_msg = MessageFactory.create_register_message(
                self.peer_id, 
                self.listen_ip, 
                self.listen_port
            )
            peer_socket.sendall(register_msg.to_bytes())
            
            # Start thread to receive messages from this peer
            recv_thread = threading.Thread(
                target=self._handle_peer_connection,
                args=(peer_socket, (peer_ip, peer_port)),
                daemon=True
            )
            recv_thread.start()
            
            return True
            
        except Exception as e:
            print(f"[Peer {self.peer_id}] Error connecting to {peer_id}: {e}")
            return False
    
    
    def send_message(self, text, recipient=None):
        """
        Send text message to specific peer or broadcast to all.
        
        :param text (str): Message text
        :param recipient (str): Recipient peer ID (None for broadcast)
        :rtype bool: True if sent successfully
        """
        try:
            # Create message
            message = MessageFactory.create_text_message(self.peer_id, text, recipient)
            
            if recipient:
                # Send to specific peer
                if recipient in self.peer_connections:
                    self.peer_connections[recipient].sendall(message.to_bytes())
                    print(f"[Peer {self.peer_id}] Sent to {recipient}: {text}")
                    return True
                else:
                    print(f"[Peer {self.peer_id}] Not connected to {recipient}")
                    return False
            else:
                # Broadcast to all connected peers
                with self.lock:
                    for peer_id, conn in self.peer_connections.items():
                        try:
                            conn.sendall(message.to_bytes())
                        except Exception as e:
                            print(f"[Peer {self.peer_id}] Error sending to {peer_id}: {e}")
                
                print(f"[Peer {self.peer_id}] Broadcast: {text}")
                return True
                
        except Exception as e:
            print(f"[Peer {self.peer_id}] Error sending message: {e}")
            return False
    
    
    def send_channel_message(self, channel_name, text):
        """
        Send message to a specific channel.
        
        :param channel_name (str): Channel name
        :param text (str): Message text
        :rtype bool: True if sent successfully
        """
        try:
            # Check if in channel
            if channel_name not in self.channels:
                print(f"[Peer {self.peer_id}] Not in channel #{channel_name}")
                return False
            
            # Create message
            message = MessageFactory.create_channel_message(self.peer_id, channel_name, text)
            
            # Send to all peers in channel
            channel_peers = self.channels[channel_name]
            sent_count = 0
            
            with self.lock:
                for peer_id in channel_peers:
                    if peer_id in self.peer_connections:
                        try:
                            self.peer_connections[peer_id].sendall(message.to_bytes())
                            sent_count += 1
                        except Exception as e:
                            print(f"[Peer {self.peer_id}] Error sending to {peer_id}: {e}")
            
            print(f"[Peer {self.peer_id}] Sent to #{channel_name} ({sent_count} peers): {text}")
            return sent_count > 0
            
        except Exception as e:
            print(f"[Peer {self.peer_id}] Error sending channel message: {e}")
            return False
    
    
    def join_channel(self, channel_name):
        """
        Join a chat channel.
        
        :param channel_name (str): Channel name to join
        """
        with self.lock:
            if channel_name not in self.channels:
                self.channels[channel_name] = []
            
            # Add self to channel
            if self.peer_id not in self.channels[channel_name]:
                self.channels[channel_name].append(self.peer_id)
        
        print(f"[Peer {self.peer_id}] Joined channel #{channel_name}")
    
    
    def get_message_history(self):
        """
        Get message history.
        
        :rtype list: List of (timestamp, sender, message) tuples
        """
        with self.lock:
            return self.message_history.copy()
    
    
    def list_connected_peers(self):
        """
        List all currently connected peers.
        
        :rtype list: List of peer IDs
        """
        with self.lock:
            return list(self.peer_connections.keys())
    
    
    def stop(self):
        """
        Stop the peer and close all connections.
        """
        print(f"[Peer {self.peer_id}] Stopping...")
        
        self.running = False
        
        # Close all peer connections
        with self.lock:
            for peer_id, conn in self.peer_connections.items():
                try:
                    conn.close()
                except:
                    pass
            self.peer_connections.clear()
        
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print(f"[Peer {self.peer_id}] Stopped")     