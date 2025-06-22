import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff, IP
import threading
import time

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer GUI")
        self.root.geometry("900x600")

        self.running = False
        self.sniff_thread = None

        self.create_widgets()

    def create_widgets(self):
        # Settings frame
        settings_frame = tk.Frame(self.root)
        settings_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(settings_frame, text="Interface:").pack(side=tk.LEFT)
        self.iface_entry = tk.Entry(settings_frame, width=15)
        self.iface_entry.insert(0, "eth0")
        self.iface_entry.pack(side=tk.LEFT, padx=5)

        tk.Label(settings_frame, text="Packet Count:").pack(side=tk.LEFT)
        self.count_entry = tk.Entry(settings_frame, width=10)
        self.count_entry.insert(0, "10")
        self.count_entry.pack(side=tk.LEFT, padx=5)

        self.start_button = tk.Button(settings_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=10)

        self.stop_button = tk.Button(settings_frame, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT)

        # Packet display table
        columns = ('No', 'Source', 'Destination', 'Protocol')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200 if col!='No' else 50)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Packet details display
        self.details_text = tk.Text(self.root, height=10, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.details_text.insert(tk.END, "Packet details will appear here...\n")

    def start_sniffing(self):
        iface = self.iface_entry.get().strip()
        try:
            count = int(self.count_entry.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Input", "Packet count must be an integer.")
            return

        if not iface:
            messagebox.showerror("Invalid Input", "Interface cannot be empty.")
            return

        self.tree.delete(*self.tree.get_children())
        self.details_text.delete("1.0", tk.END)
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

        # Start sniffing in a thread
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(iface, count))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_sniffing(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, iface, count):
        try:
            sniff(iface=iface, prn=self.process_packet, store=False, count=count)
        except Exception as e:
            messagebox.showerror("Error", f"Sniffing error: {e}")
        finally:
            self.running = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def process_packet(self, packet):
        if not self.running:
            return False

        if IP in packet:
            idx = len(self.tree.get_children()) + 1
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, str(proto))
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))
            payload = bytes(packet[IP].payload)

            self.tree.insert('', 'end', values=(idx, src, dst, proto_name))

            details = (
                f"Packet #{idx}:\n"
                f"Timestamp: {timestamp}\n"
                f"Source IP: {src}\n"
                f"Destination IP: {dst}\n"
                f"Protocol: {proto_name}\n"
                f"Payload: {payload[:60]!r}...\n\n"
            )

            self.details_text.insert(tk.END, details)
            self.details_text.see(tk.END)

# Run GUI
if __name__ == '__main__':
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
