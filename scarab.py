import tkinter as tk
from tkinter import filedialog, messagebox
from scapy.all import *

def analyze_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        return "File not found."
    except Exception as e:
        return f"Error reading pcap file: {e}"

    suspicious_traffic = []
    suspicious_count = 0
    output = ""

    
    output += "Analyzing the PCAP file...\n\n"

    for i, pkt in enumerate(packets, 1):
        if TCP in pkt:
            if pkt.haslayer(Raw) and (pkt[TCP].dport == 80 or pkt[TCP].dport == 443):
                raw_layer = pkt.getlayer(Raw)
                if raw_layer:
                    if b"ransomware" in raw_layer.load.lower():
                        suspicious_traffic.append(pkt)
                        suspicious_count += 1
                        
                        if b"GET" in raw_layer.load:
                            start_index = raw_layer.load.find(b"GET") + 4
                            end_index = raw_layer.load.find(b"HTTP")
                            file_path = raw_layer.load[start_index:end_index].strip()
                            output += f"Packet {i}: Potentially infected file: {file_path.decode()}\n"
                            output += f"Timestamp: {pkt.time}\n"
                            output += f"Protocol: HTTP\n"
                            output += f"Source IP: {pkt[IP].src}\n"
                            output += f"Destination IP: {pkt[IP].dst}\n"
                            output += f"Source Port: {pkt[TCP].sport}\n"
                            output += f"Destination Port: {pkt[TCP].dport}\n"
                            output += f"Packet Size: {len(pkt)}\n"
                            output += f"Packet Payload: {pkt.load.decode()}\n\n"
            
            elif pkt[TCP].flags & 2:  
                suspicious_traffic.append(pkt)
                suspicious_count += 1
                output += f"Packet {i}: Suspicious SYN packet detected:\n"
                output += f"Timestamp: {pkt.time}\n"
                output += f"Protocol: TCP\n"
                output += f"Source IP: {pkt[IP].src}\n"
                output += f"Destination IP: {pkt[IP].dst}\n"
                output += f"Source Port: {pkt[TCP].sport}\n"
                output += f"Destination Port: {pkt[TCP].dport}\n"
                output += f"Packet Size: {len(pkt)}\n\n"
        elif UDP in pkt:
           
            if pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
                raw_layer = pkt.getlayer(Raw)
                if raw_layer:
                    if b"ransomware" in raw_layer.load.lower():
                        suspicious_traffic.append(pkt)
                        suspicious_count += 1
                        output += f"Packet {i}: Suspicious DNS query detected:\n"
                        output += f"Timestamp: {pkt.time}\n"
                        output += f"Protocol: DNS\n"
                        output += f"Source IP: {pkt[IP].src}\n"
                        output += f"Destination IP: {pkt[IP].dst}\n"
                        output += f"Source Port: {pkt[UDP].sport}\n"
                        output += f"Destination Port: {pkt[UDP].dport}\n"
                        output += f"Packet Size: {len(pkt)}\n"
                        output += f"Query: {pkt[DNS].qd.qname.decode()}\n\n"

    if suspicious_traffic:
        output += f"Total suspicious activities detected: {suspicious_count}\n"
        for i, pkt in enumerate(suspicious_traffic, 1):
            output += f"<Packet {i}> summary: {pkt.summary()}\n"
    else:
        output += "No suspicious activity detected."

    return output

def browse_file():
    filename = filedialog.askopenfilename()
    entry_file_path.delete(0, tk.END)
    entry_file_path.insert(0, filename)

def analyze_file():
    filename = entry_file_path.get()
    if not filename:
        messagebox.showerror("Error", "Please enter the file path.")
        return

    output = analyze_pcap(filename)

    text_output.delete("1.0", tk.END)
    text_output.insert(tk.END, output)


root = tk.Tk()
root.title("Ransomware Analysis Tool")
root.geometry("400x300")


frame = tk.Frame(root)
frame.pack(pady=20)


label_file_path = tk.Label(frame, text="Enter the path to the PCAP file:")
label_file_path.grid(row=0, column=0, padx=10, pady=5)

entry_file_path = tk.Entry(frame, width=50)
entry_file_path.grid(row=0, column=1, padx=10, pady=5)

button_frame = tk.Frame(root)
button_frame.pack(pady=(0, 10))

button_browse = tk.Button(button_frame, text="Browse", command=browse_file)
button_browse.pack(side=tk.LEFT, padx=5)

button_analyze = tk.Button(button_frame, text="Analyze", command=analyze_file)
button_analyze.pack(side=tk.LEFT, padx=5)

text_output = tk.Text(root, wrap=tk.WORD, width=75, height=10)
text_output.pack(padx=20, pady=(0, 10))


root.mainloop()
