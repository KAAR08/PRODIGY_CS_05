import tkinter as tk
from customtkinter import CTk, CTkButton, CTkLabel, CTkFrame, CTkScrollbar
from scapy.all import sniff
from scapy.layers.inet import IP
from datetime import datetime


class PacketAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("900x600")
        self.root.resizable(False, False)
        
        # Title
        self.title_label = CTkLabel(
            root, text="📡 Network Packet Analyzer", 
            font=("Arial Bold", 24), fg_color="#4682b4", 
            text_color="white", corner_radius=8, width=800, height=50)
        self.title_label.pack(pady=10)
        
        # Table Frame
        self.table_frame = CTkFrame(root, width=880, height=400, fg_color="white", corner_radius=8)
        self.table_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        
        # Scrollable Table Content
        self.table_canvas = tk.Canvas(self.table_frame, bg="white", height=340, width=860, highlightthickness=0)
        self.table_canvas.grid(row=1, column=0, sticky="nsew")
        
        #Vertical scrollbar linked to the canvas above
        self.table_scrollbar = CTkScrollbar(self.table_frame, orientation="vertical", command=self.table_canvas.yview)
        self.table_scrollbar.grid(row=1, column=1, sticky="ns")
        
        #dynamically updates scrollable region as content is added to the canvas
        self.table_canvas.configure(yscrollcommand=self.table_scrollbar.set)
        self.table_content_frame = tk.Frame(self.table_canvas, bg="white")
        self.table_canvas.create_window((0, 0), window=self.table_content_frame, anchor="nw")
        self.table_content_frame.bind("<Configure>", lambda e: self.table_canvas.configure(scrollregion=self.table_canvas.bbox("all")))
        
        # Column Headers for the table
        headers = ["Time Stamp", "Source Address", "Destination Address", "Protocol", "Payload Data"]
        for col, header in enumerate(headers):
            label = tk.Label(
                self.table_content_frame, text=header, bg="lightgrey", fg="black", 
                font=("Arial Bold", 12), relief=tk.RIDGE, padx=5, pady=2)
            label.grid(row=0, column=col, sticky="nsew", padx=2, pady=2) #placing column headers in the first row
        
        # Configure grid weights for proper column resizing
        self.table_content_frame.columnconfigure(0, weight=1)  
        self.table_content_frame.columnconfigure(1, weight=1)  
        self.table_content_frame.columnconfigure(2, weight=1)  
        self.table_content_frame.columnconfigure(3, weight=1)  
        self.table_content_frame.columnconfigure(4, weight=5)  

        # Buttons
        self.start_button = CTkButton(root, text="Start Capture", command=self.start_sniffing, fg_color="#32cd32", hover_color="#228b22")
        self.start_button.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.stop_button = CTkButton(root, text="Stop Capture", command=self.stop_sniffing, fg_color="#cd5c5c", hover_color="#8b0000")
        self.stop_button.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.clear_button = CTkButton(root, text="Clear Data", command=self.clear_table, fg_color="#4682b4", hover_color="#4169e1")
        self.clear_button.pack(side=tk.LEFT, padx=20, pady=10)
        
        # Packet Capture State initialization
        self.sniffing = False #checks whether packet capture is ongoing
        self.packet_count = 1  
        
        
    #Starting packet capture
    def start_sniffing(self):
        if not self.sniffing:
            self.sniffing = True
            self.packet_count = 1
            self.capture_thread = self.root.after(100, self.capture_packets)
    
    
    #Stoping packet capture
    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            
    
    #Clearing the table contents
    def clear_table(self):
        for widget in self.table_content_frame.winfo_children():
            widget.destroy()
            
        headers = ["Time Stamp", "Source Address", "Destination Address", "Protocol", "Payload Data"]
        for col, header in enumerate(headers):
            label = tk.Label(
                self.table_content_frame, text=header, bg="lightgrey", fg="black", 
                font=("Arial Bold", 12), relief=tk.RIDGE, padx=5, pady=2)
            label.grid(row=0, column=col, sticky="nsew", padx=2, pady=2)
        self.packet_count = 1 
         
    #Updating the table with a new row
    def update_table(self, data):
        for col, value in enumerate(data):
            label = tk.Label(
                self.table_content_frame, text=value, bg="white", anchor="w", 
                font=("Arial", 10), relief=tk.RIDGE, padx=5, pady=2)
            label.grid(row=self.packet_count, column=col, sticky="nsew", padx=2, pady=2)
        self.packet_count += 1  
        
    
    #Capturing packets using Scapy
    def capture_packets(self):
        if self.sniffing:
            sniff(prn=self.process_packet, count=5, timeout=1)  # Capture 5 packets at a time
            self.capture_thread = self.root.after(100, self.capture_packets)
    
    
    #Processing captured packets
    def process_packet(self, packet):
        if IP in packet:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            payload = str(packet[IP].payload)[:100]  # Increase payload to show more data
            self.update_table([timestamp, src, dst, proto, payload])


if __name__ == "__main__":
    app = CTk()
    analyzer = PacketAnalyzerApp(app)
    app.mainloop()
