
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import threading
import time

class PacketSnifferGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Analyzer")
        self.root.geometry("1100x700")
        self.root.configure(bg="#1e1e2f")

        self.running = False

        title = tk.Label(
            root,
            text="Network Packet Analyzer",
            font=("Arial", 22, "bold"),
            bg="#1e1e2f",
            fg="white"
        )
        title.pack(pady=10)

        button_frame = tk.Frame(root, bg="#1e1e2f")
        button_frame.pack(pady=10)

        self.start_btn = tk.Button(
            button_frame,
            text="Start Sniffing",
            font=("Arial", 12, "bold"),
            bg="green",
            fg="white",
            width=18,
            command=self.start_sniffing
        )
        self.start_btn.grid(row=0, column=0, padx=10)

        self.stop_btn = tk.Button(
            button_frame,
            text="Stop Sniffing",
            font=("Arial", 12, "bold"),
            bg="red",
            fg="white",
            width=18,
            command=self.stop_sniffing
        )
        self.stop_btn.grid(row=0, column=1, padx=10)

        self.clear_btn = tk.Button(
            button_frame,
            text="Clear Output",
            font=("Arial", 12, "bold"),
            bg="#007acc",
            fg="white",
            width=18,
            command=self.clear_output
        )
        self.clear_btn.grid(row=0, column=2, padx=10)

        self.packet_count = 0

        self.counter_label = tk.Label(
            root,
            text="Packets Captured: 0",
            font=("Arial", 12, "bold"),
            bg="#1e1e2f",
            fg="yellow"
        )
        self.counter_label.pack()

        self.output_area = scrolledtext.ScrolledText(
            root,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="black",
            fg="lime",
            insertbackground="white"
        )

        self.output_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)


        ethical_notice = tk.Label(
            root,
            text="Educational Use Only - Do Not Capture Unauthorized Traffic",
            font=("Arial", 10, "italic"),
            bg="#1e1e2f",
            fg="orange"
        )
        ethical_notice.pack(pady=5)

    def start_sniffing(self):

        if not self.running:
            self.running = True

            self.output_area.insert(
                tk.END,
                "\n[+] Packet sniffing started...\n\n"
            )

            sniff_thread = threading.Thread(target=self.sniff_packets)
            sniff_thread.daemon = True
            sniff_thread.start()

    def stop_sniffing(self):

        self.running = False

        self.output_area.insert(
            tk.END,
            "\n[-] Packet sniffing stopped.\n\n"
        )

    def clear_output(self):

        self.output_area.delete(1.0, tk.END)
        self.packet_count = 0
        self.counter_label.config(text="Packets Captured: 0")

    def sniff_packets(self):

        sniff(
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def process_packet(self, packet):

        if not self.running:
            return True

        self.packet_count += 1

        self.counter_label.config(
            text=f"Packets Captured: {self.packet_count}"
        )

        packet_info = "\n" + "=" * 80 + "\n"
        packet_info += f"Packet #{self.packet_count}\n"
        packet_info += f"Time: {time.strftime('%H:%M:%S')}\n"

        if packet.haslayer(IP):

            ip_layer = packet[IP]

            packet_info += f"Source IP      : {ip_layer.src}\n"
            packet_info += f"Destination IP : {ip_layer.dst}\n"
            packet_info += f"Protocol        : {ip_layer.proto}\n"

            if packet.haslayer(TCP):

                tcp_layer = packet[TCP]

                packet_info += "Protocol Name   : TCP\n"
                packet_info += f"Source Port     : {tcp_layer.sport}\n"
                packet_info += f"Destination Port: {tcp_layer.dport}\n"

            elif packet.haslayer(UDP):

                udp_layer = packet[UDP]

                packet_info += "Protocol Name   : UDP\n"
                packet_info += f"Source Port     : {udp_layer.sport}\n"
                packet_info += f"Destination Port: {udp_layer.dport}\n"

            elif packet.haslayer(ICMP):

                packet_info += "Protocol Name   : ICMP\n"

            if packet.haslayer(Raw):

                payload = packet[Raw].load

                try:
                    payload = payload.decode(errors="ignore")
                except:
                    payload = str(payload)

                packet_info += f"\nPayload Data:\n{payload[:500]}\n"

        else:
            packet_info += "Non-IP Packet Captured\n"

        packet_info += "=" * 80 + "\n"

        self.output_area.insert(tk.END, packet_info)
        self.output_area.see(tk.END)

if __name__ == "__main__":

    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()