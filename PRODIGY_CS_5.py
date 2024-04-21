import tkinter as tk
import pyshark
import platform
import subprocess
import threading
from tkinter import messagebox
from tkinter import filedialog

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        # Interface selection
        self.interface_selection = tk.StringVar()
        self.interface_label = tk.Label(root, text="Select Interface:")
        self.interface_label.grid(row=0, column=0, padx=10, pady=5)
        self.interface_dropdown = tk.OptionMenu(root, self.interface_selection, ())
        self.interface_dropdown.grid(row=0, column=1, padx=10, pady=5)

        # Start button
        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.grid(row=1, column=0, padx=10, pady=5)

        # Stop button
        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.grid(row=1, column=1, padx=10, pady=5)

        # Save button
        self.save_button = tk.Button(root, text="Save", command=self.save_capture, state=tk.DISABLED)
        self.save_button.grid(row=1, column=2, padx=10, pady=5)

        # Clear button
        self.clear_button = tk.Button(root, text="Clear Output", command=self.clear_output)
        self.clear_button.grid(row=2, column=0, columnspan=3, padx=10, pady=5)

        # Output text area
        self.output_text = tk.Text(root, height=15, width=80)
        self.output_text.grid(row=3, column=0, columnspan=3, padx=10, pady=5)

        # Populate interfaces
        self.populate_interfaces()

        # Flag to control packet capture
        self.capture_flag = threading.Event()

    def populate_interfaces(self):
        interfaces = self.list_available_interfaces()
        if interfaces:
            self.interface_selection.set(interfaces[0])
            menu = self.interface_dropdown["menu"]
            menu.delete(0, "end")
            for interface in interfaces:
                menu.add_command(label=interface, command=tk._setit(self.interface_selection, interface))

    def list_available_interfaces(self):
        interfaces = []
        system = platform.system()
        if system == "Darwin" or system == "Linux":
            try:
                ifconfig_result = subprocess.run(["ifconfig"], capture_output=True, text=True)
                interfaces = [line.split(":")[0] for line in ifconfig_result.stdout.split("\n") if line.strip() and not line.startswith(" ")]
            except Exception as e:
                self.show_error_message(f"Error listing interfaces: {e}")
        elif system == "Windows":
            try:
                ipconfig_result = subprocess.run(["ipconfig"], capture_output=True, text=True)
                interfaces = [line.split(":")[0].strip() for line in ipconfig_result.stdout.split("\n") if "adapter" in line]
            except Exception as e:
                self.show_error_message(f"Error listing interfaces: {e}")
        else:
            self.show_error_message("Unsupported platform.")
        return interfaces

    def analyze_packet(self, packet):
        try:
            protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'
            source_ip = packet.ip.src_host if hasattr(packet, 'ip') and hasattr(packet.ip, 'src_host') else 'Unknown'
            destination_ip = packet.ip.dst_host if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst_host') else 'Unknown'
            payload = self.decode_payload(packet)

            return {
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "payload": payload
            }
        except Exception as e:
            self.show_error_message(f"Error analyzing packet: {e}")

    def decode_payload(self, packet):
        try:
            if isinstance(packet, str):
                # If packet is a string, return it directly
                return packet
            else:
                highest_layer = packet.highest_layer
                if highest_layer == "HTTP":
                    return packet.http.request_uri if hasattr(packet.http, 'request_uri') else 'Unknown'
                elif highest_layer == "DNS":
                    return packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'Unknown'
                else:
                    # For other protocols, return the raw packet data
                    return str(packet.layers[-1])
        except Exception as e:
            self.show_error_message(f"Error decoding payload: {e}")
            return ""

    def display_output(self, packet_details):
        try:
            self.output_text.insert(tk.END, f"Protocol: {packet_details['protocol']}\n")
            self.output_text.insert(tk.END, f"Source IP: {packet_details['source_ip']}\n")
            self.output_text.insert(tk.END, f"Destination IP: {packet_details['destination_ip']}\n")
            self.output_text.insert(tk.END, f"Payload: {packet_details['payload']}\n\n")
        except Exception as e:
            self.show_error_message(f"Error displaying output: {e}")

    def clear_output(self):
        self.output_text.delete("1.0", tk.END)

    def start_capture(self):
        interface = self.interface_selection.get()
        if not interface:
            self.show_error_message("Please select an interface.")
            return

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.capture_flag.clear()  # Clear the flag to start capturing
        capture_thread = threading.Thread(target=self.capture_packets, args=(interface,))
        capture_thread.start()

    def stop_capture(self):
        self.capture_flag.set()  # Set the flag to stop capturing
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.save_button.config(state=tk.NORMAL)

    def save_capture(self):
        filename = filedialog.asksaveasfilename(defaultextension=".pcap")
        if filename:
            # Implement code to save captured packets to the specified file
            pass

    def capture_packets(self, interface):
        try:
            capture = pyshark.LiveCapture(interface=interface)
            self.output_text.insert(tk.END, f"Starting capture on interface: {interface}\n")
            for packet in capture.sniff_continuously():
                if self.capture_flag.is_set():  # Check if the flag is set to stop capturing
                    self.output_text.insert(tk.END, "Capture stopped.\n")
                    self.start_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    self.save_button.config(state=tk.NORMAL)
                    break
                packet_details = self.analyze_packet(packet)
                if packet_details:
                    self.display_output(packet_details)
        except Exception as e:
            self.show_error_message(f"Error capturing packets: {e}")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.save_button.config(state=tk.NORMAL)

    def show_error_message(self, message):
        messagebox.showerror("Error", message)


def main():
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
