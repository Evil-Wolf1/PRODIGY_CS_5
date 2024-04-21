# Network Packet Analyzer

## Description
This project is a network packet analyzer implemented in Python. It allows users to capture, analyze, and display network packets from a selected interface using a graphical user interface (GUI).

## Features
- Select network interface from a dropdown menu.
- Start and stop packet capture.
- Display captured packet details including protocol, source IP, destination IP, and payload.
- Save captured packets to a file.

## Dependencies
- Python 3.x
- pyshark
- tkinter (usually included in Python standard library)
- platform (usually included in Python standard library)

## Installation
1. Clone or download the project from GitHub.
2. Install the required dependencies using pip:
 
## Usage
1. Run the application by executing the `Task-05.py` file:
2. Select the network interface from the dropdown menu.
3. Click on the "Start Capture" button to begin capturing packets.
4. To stop the capture, click on the "Stop Capture" button.
5. Captured packet details will be displayed in the output area.
6. Click on the "Save" button to save captured packets to a file.
7. Click on the "Clear Output" button to clear the output area.

## Known Issues
- Currently, the save functionality is implemented as a placeholder and does not actually save captured packets to a file.

## Contributing
Contributions are welcome! If you find any bugs or have suggestions for improvements, please open an issue or submit a pull request.

## License
[MIT License](LICENSE)
