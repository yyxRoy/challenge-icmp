// icmp_authenticator.c

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <linux/slab.h>
#include <linux/inet.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h> // 正确的以太网头文件
#include <net/sock.h>      // 添加此行

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Kernel module to authenticate ICMP error messages");

#define IP_OPTION_VENDOR_SPECIFIC 0x7F
#define IP_OPTION_HASH_LEN 12 // 类型(1) + 长度(1) + 数据(8) + 填充(2)

struct challenge_entry {
    __u32 src_ip;                 // Original packet's source IP
    __u32 dest_ip;                // Original packet's destination IP
    __u64 challenge_hash;         // Hash value
    struct rhash_head node;       // Hash table node
};

/* Define the hash table */
static struct rhashtable challenge_table;

/* Hash table parameters */
static struct rhashtable_params challenge_params = {
    .key_len = sizeof(__u32) * 2, // src_ip + dest_ip
    .key_offset = offsetof(struct challenge_entry, src_ip),
    .head_offset = offsetof(struct challenge_entry, node),
    .automatic_shrinking = true,
};

/* Function to generate a random hash */
static __u64 generate_challenge_hash(__u32 src_ip, __u32 dest_ip) {
    __u64 hash;
    get_random_bytes(&hash, sizeof(hash)); // Use kernel's random generator
    return hash;
}

/* Function to add a challenge entry to the hash table */
static void add_challenge(__u32 src_ip, __u32 dest_ip, __u64 hash) {
    struct challenge_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        printk(KERN_ERR "ICMP Authenticator: Failed to allocate memory for challenge entry\n");
        return;
    }

    entry->src_ip = src_ip;
    entry->dest_ip = dest_ip;
    entry->challenge_hash = hash;

    if (rhashtable_insert_fast(&challenge_table, &entry->node, challenge_params)) {
        printk(KERN_ERR "ICMP Authenticator: Failed to insert challenge entry into hash table\n");
        kfree(entry);
    } else {
        printk(KERN_INFO "ICMP Authenticator: Added challenge entry (src: %pI4, dest: %pI4, hash: %llu)\n",
               &entry->src_ip, &entry->dest_ip, entry->challenge_hash);
    }
}

/* Function to validate a challenge response with MAC address */
static bool validate_challenge(__u32 src_ip, __u32 dest_ip, __u64 received_hash, unsigned char *src_mac) {
    struct challenge_entry *entry;
    struct challenge_entry lookup;

    lookup.src_ip = src_ip;
    lookup.dest_ip = dest_ip;

    /* Lookup the challenge entry */
    entry = rhashtable_lookup_fast(&challenge_table, &lookup.src_ip, challenge_params);
    if (entry && entry->dest_ip == dest_ip && entry->challenge_hash == received_hash) {

        /* Valid challenge response */
        printk(KERN_INFO "ICMP Authenticator: Valid challenge response received (src: %pI4, dest: %pI4, hash: %llu)\n",
               &src_ip, &dest_ip, received_hash);

        /* Remove the entry from the hash table */
        rhashtable_remove_fast(&challenge_table, &entry->node, challenge_params);
        kfree(entry);
        return true;
    }

    /* Invalid challenge response */
    printk(KERN_INFO "ICMP Authenticator: Invalid challenge response received (src: %pI4, dest: %pI4, hash: %llu)\n",
           &src_ip, &dest_ip, received_hash);
    return false;
}

/* Function to extract hash from IP options */
static bool extract_hash_from_options(struct iphdr *original_ip, __u64 *hash) {
    unsigned char *options;
    int options_len;
    int i = 0;
    unsigned char opt_type;
    unsigned char opt_len;

    /* Check if there are IP options */
    if (original_ip->ihl <= 5)
        return false;

    options_len = (original_ip->ihl - 5) * 4;
    options = (unsigned char *)(original_ip + 1);

    while (i < options_len) {
        opt_type = options[i];
        if (opt_type == 0) { // End of Option List
            break;
        } else if (opt_type == 1) { // No Operation
            i += 1;
            continue;
        } else {
            if (i + 1 >= options_len) {
                break; // Not enough data
            }
            opt_len = options[i + 1];
            if (opt_len < 2 || i + opt_len > options_len) {
                break; // Invalid option length
            }

            if (opt_type == IP_OPTION_VENDOR_SPECIFIC && opt_len >= IP_OPTION_HASH_LEN) { // Vendor-Specific Option with at least 8 bytes hash
                memcpy(hash, &options[i + 2], sizeof(__u64));
                return true;
            }

            i += opt_len;
        }
    }

    return false;
}

/* Function to remove IP options from the original IP header inside ICMP payload */
static void remove_ip_options(struct sk_buff *skb, struct iphdr *original_ip, struct icmphdr *icmp_header) {
    // 确保 skb 可写
    if (!skb_try_make_writable(skb, skb->len)) { // 或者使用 skb_try_make_writable(skb, skb->len) 根据您的内核版本
        printk(KERN_ERR "ICMP Authenticator: Failed to make skb writable\n");
        return;
    }

    // 检查 original_ip 是否为 NULL
    if (!original_ip) {
        printk(KERN_ERR "ICMP Authenticator: original_ip is NULL\n");
        return;
    }

    // 检查原始 IP 头部是否包含 IP 选项
    if (original_ip->ihl <= 5) {
        printk(KERN_INFO "ICMP Authenticator: Original IP header has no options\n");
        return;
    }

    // 存储原始 IHL
    int original_ihl = original_ip->ihl;

    // 设置 IHL 为 5，表示无 IP 选项
    original_ip->ihl = 5;

    // 计算需要移除的选项长度
    int options_len = (original_ihl - 5) * 4;

    // 清零 IP 选项
    unsigned char *options = (unsigned char *)(original_ip + 1);
    memset(options, 0, options_len);

    // 重新计算原始 IP 头部的校验和
    original_ip->check = 0;
    original_ip->check = ip_fast_csum((unsigned char *)original_ip, original_ip->ihl);

    // 重新计算 ICMP 消息的校验和
    // ICMP 负载包含原始 IP 头部和 8 字节数据
    int icmp_payload_len = sizeof(struct iphdr) + 8;
    icmp_header->checksum = 0;
    icmp_header->checksum = ip_fast_csum((unsigned char *)icmp_header, sizeof(struct icmphdr) + icmp_payload_len);

    printk(KERN_INFO "ICMP Authenticator: Removed IP options from original IP header and updated checksums\n");
}

/* Function to send a challenge packet with hash in IP options */
static void send_challenge(struct sk_buff *skb, struct iphdr *original_ip, struct icmphdr *original_icmp, unsigned char *target_mac) {
    struct sk_buff *challenge_skb;
    struct ethhdr *eth_header;
    struct iphdr *new_ip_header;
    struct icmphdr *new_icmp_header;
    __u64 hash;
    int icmp_payload_size = 1410; // ICMP payload size
    int ip_options_size = IP_OPTION_HASH_LEN;
    int len;
    unsigned char *ip_options;
    unsigned char options_buffer[IP_OPTION_HASH_LEN];
    char *icmp_payload;
    struct net_device *dev;
    unsigned char src_mac[ETH_ALEN];
    int ret;

    /* Get the sending device */
    dev = skb->dev;
    if (!dev) {
        printk(KERN_ERR "ICMP Authenticator: skb->dev is NULL\n");
        return;
    }

    /* Get source MAC address */
    memcpy(src_mac, dev->dev_addr, ETH_ALEN);

    /* Target MAC address is provided via parameter (target_mac) */

    /* Generate random hash */
    hash = generate_challenge_hash(original_ip->saddr, original_ip->daddr);

    /* Add challenge to the hash table */
    add_challenge(original_ip->saddr, original_ip->daddr, hash);

    /* Prepare IP options with embedded hash */
    memset(options_buffer, 0, IP_OPTION_HASH_LEN);
    options_buffer[0] = IP_OPTION_VENDOR_SPECIFIC; // Option type
    options_buffer[1] = IP_OPTION_HASH_LEN;        // Option length
    memcpy(&options_buffer[2], &hash, sizeof(__u64)); // Embed hash
    // Pad remaining bytes with 0
    memset(&options_buffer[10], 0, IP_OPTION_HASH_LEN - 10);

    /* Calculate new IP header length (base IHL 5 + options length / 4) */
    len = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) + ip_options_size + icmp_payload_size;

    /* Allocate new skb for sending challenge packet */
    challenge_skb = alloc_skb(len + LL_RESERVED_SPACE(dev), GFP_ATOMIC);
    if (!challenge_skb) {
        printk(KERN_ERR "ICMP Authenticator: Failed to allocate memory for challenge skb\n");
        return;
    }

    skb_reserve(challenge_skb, LL_RESERVED_SPACE(dev));
    skb_put(challenge_skb, len);

    /* Fill Ethernet header */
    eth_header = (struct ethhdr *)skb_push(challenge_skb, sizeof(struct ethhdr));
    memcpy(eth_header->h_dest, target_mac, ETH_ALEN); // Target MAC
    memcpy(eth_header->h_source, src_mac, ETH_ALEN); // Source MAC
    eth_header->h_proto = htons(ETH_P_IP); // Ethernet type: IP

    /* Fill new IP header */
    new_ip_header = (struct iphdr *)(eth_header + 1);
    memset(new_ip_header, 0, sizeof(struct iphdr));
    new_ip_header->version = 4;
    new_ip_header->ihl = 5 + (ip_options_size / 4); // IHL includes options
    new_ip_header->tos = 0;
    new_ip_header->tot_len = htons(sizeof(struct iphdr) + ip_options_size + sizeof(struct icmphdr) + icmp_payload_size);
    new_ip_header->id = 0;
    new_ip_header->frag_off = htons(IP_DF);
    new_ip_header->ttl = 64;
    new_ip_header->protocol = IPPROTO_ICMP;
    new_ip_header->saddr = original_ip->saddr; // Source IP: original source IP (local IP)
    new_ip_header->daddr = original_ip->daddr; // Destination IP: original destination IP

    /* Copy IP options */
    ip_options = (unsigned char *)(new_ip_header + 1);
    memcpy(ip_options, options_buffer, ip_options_size);

    /* Compute IP header checksum */
    new_ip_header->check = 0;
    new_ip_header->check = ip_fast_csum((unsigned char *)new_ip_header, new_ip_header->ihl);

    /* Fill ICMP header */
    new_icmp_header = (struct icmphdr *)(ip_options + ip_options_size);
    new_icmp_header->type = ICMP_ECHO; // ICMP Echo Request
    new_icmp_header->code = 0;         // Code 0 for Echo Request
    new_icmp_header->checksum = 0;
    new_icmp_header->un.echo.id = htons(0x1234); // Example ID
    new_icmp_header->un.echo.sequence = htons(0x0001); // Example sequence number

    /* Embed hash into first 8 bytes of ICMP payload */
    icmp_payload = (char *)(new_icmp_header + 1);
    memcpy(icmp_payload, &hash, sizeof(__u64));

    /* Fill remaining ICMP payload with random data */
    get_random_bytes(icmp_payload + sizeof(__u64), icmp_payload_size - sizeof(__u64));

    /* Compute ICMP checksum */
    new_icmp_header->checksum = ip_fast_csum((unsigned char *)new_icmp_header, sizeof(struct icmphdr) + icmp_payload_size);

    /* Set skb->protocol */
    challenge_skb->protocol = eth_header->h_proto;

    /* Set network device */
    challenge_skb->dev = dev;

    /* Set other necessary skb fields */
    skb_reset_network_header(challenge_skb);
    skb_reset_transport_header(challenge_skb);

    /* Send the packet */
    ret = dev_queue_xmit(challenge_skb);
    if (ret < 0) {
        printk(KERN_ERR "ICMP Authenticator: Failed to send challenge packet, ret = %d\n", ret);
    } else {
        printk(KERN_INFO "ICMP Authenticator: Sent ICMP Echo Challenge packet to %pI4 with payload size %d bytes\n", &new_ip_header->daddr, icmp_payload_size);
    }
}

/* Function to handle received ICMP error messages */
static bool handle_icmp_error(struct sk_buff *skb, struct iphdr *ip_header, struct icmphdr *icmp_header, unsigned char *src_mac, unsigned char *dest_mac) {
    struct iphdr *original_ip;
    int ihl;
    __u32 original_src_ip, original_dest_ip;
    bool has_hash;
    __u64 received_hash;

    /* 确保有足够的数据包含原始 IP 头 */
    ihl = ip_header->ihl * 4;
    if (ihl + sizeof(struct icmphdr) + sizeof(struct iphdr) > ntohs(ip_header->tot_len)) {
        printk(KERN_INFO "ICMP Authenticator: ICMP error message too short to contain original IP header\n");
        return false;
    }

    /* 从 ICMP 负载中提取原始 IP 头 */
    original_ip = (struct iphdr *)((unsigned char *)icmp_header + sizeof(struct icmphdr));
    if (!original_ip) {
        printk(KERN_INFO "ICMP Authenticator: Failed to extract original IP header\n");
        return false;
    }

    /* 确保原始 IP 头部在 skb 数据范围内 */
    if ((unsigned char *)original_ip + sizeof(struct iphdr) > skb->data + skb->len) {
        printk(KERN_INFO "ICMP Authenticator: Original IP header exceeds skb data\n");
        return false;
    }

    /* 提取原始源和目的 IP 地址 */
    original_src_ip = original_ip->saddr;
    original_dest_ip = original_ip->daddr;

    printk(KERN_INFO "ICMP Authenticator: Handling ICMP error for original src: %pI4, dest: %pI4\n",
           &original_src_ip, &original_dest_ip);

    /* 可选：使用 MAC 地址进行额外验证 */
    printk(KERN_INFO "ICMP Authenticator: Source MAC: %pM, Destination MAC: %pM\n", src_mac, dest_mac);

    /* 检查原始 IP 报文的选项中是否包含哈希值 */
    has_hash = extract_hash_from_options(original_ip, &received_hash);
    if (has_hash) {
        /* 这是挑战响应消息 */
        /* 验证挑战 */
        if (validate_challenge(original_src_ip, original_dest_ip, received_hash, src_mac)) {
            /* 认证成功 */
            printk(KERN_INFO "ICMP Authenticator: Successfully authenticated ICMP error message from %pI4\n", &original_src_ip);

            /* 移除 ICMP 消息中原始 IP 头部的 IP 选项 */
            remove_ip_options(skb, original_ip, icmp_header);

            /* 接受消息 */
            return true; // NF_ACCEPT
        } else {
            /* 认证失败 */
            printk(KERN_INFO "ICMP Authenticator: Failed to authenticate ICMP error message from %pI4\n", &original_src_ip);
            /* 丢弃消息 */
            return false; // NF_DROP
        }
    } else {
        /* 这是初始 ICMP 错误消息，生成挑战 */
        send_challenge(skb, original_ip, icmp_header, src_mac); // 使用源 MAC 作为目标 MAC
        return false; // NF_DROP
    }
}

/* Netfilter hook function to intercept received ICMP error messages */
static unsigned int icmp_error_interceptor(void *priv, struct sk_buff *skb,
                                           const struct nf_hook_state *state) {
    struct ethhdr *eth_header;
    struct iphdr *ip_header;
    struct icmphdr *icmp_header;
    bool auth_success;
    unsigned char src_mac[ETH_ALEN];
    unsigned char dest_mac[ETH_ALEN];

    if (!skb)
        return NF_ACCEPT;

    /* Ensure the packet is long enough */
    if (skb->len < sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
        return NF_ACCEPT;

    /* Ethernet header is at skb->data */
    eth_header = eth_hdr(skb);
    if (!eth_header)
        return NF_ACCEPT;

    /* Get IP header */
    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    /* Get ICMP header */
    icmp_header = icmp_hdr(skb);
    if (!icmp_header)
        return NF_ACCEPT;

    /* Check if it's an ICMP error message (types 3-5, etc.) */
    if (icmp_header->type == ICMP_DEST_UNREACH || icmp_header->type == ICMP_REDIRECT) {
         /* Extract source and destination MAC addresses */
        memcpy(src_mac, eth_header->h_source, ETH_ALEN);
        memcpy(dest_mac, eth_header->h_dest, ETH_ALEN);

        printk(KERN_INFO "ICMP Authenticator: Captured ICMP error message (type: %d, code: %d)\n",
               icmp_header->type, icmp_header->code);

        /* Handle the ICMP error message and get authentication result */
        auth_success = handle_icmp_error(skb, ip_header, icmp_header, src_mac, dest_mac);

        if (auth_success) {
            /* Authentication successful, accept the message */
            return NF_ACCEPT;
        } else {
            /* Authentication failed or initial message, drop the packet */
            return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

/* Define Netfilter hook */
static struct nf_hook_ops nfho_icmp_error = {
    .hook = icmp_error_interceptor,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

/* Module initialization */
static int __init icmp_authenticator_init(void) {
    int ret;

    /* Initialize the hash table */
    ret = rhashtable_init(&challenge_table, &challenge_params);
    if (ret) {
        printk(KERN_ERR "ICMP Authenticator: Failed to initialize challenge hash table\n");
        return ret;
    }

    /* Register Netfilter hook */
    ret = nf_register_net_hook(&init_net, &nfho_icmp_error);
    if (ret) {
        printk(KERN_ERR "ICMP Authenticator: Failed to register ICMP error hook\n");
        rhashtable_destroy(&challenge_table);
        return ret;
    }

    printk(KERN_INFO "ICMP Authenticator: Module loaded successfully\n");
    return 0;
}

/* Module exit */
static void __exit icmp_authenticator_exit(void) {
    struct challenge_entry *entry;
    struct rhashtable_iter iter; // Define iterator

    /* Unregister Netfilter hook */
    nf_unregister_net_hook(&init_net, &nfho_icmp_error);

    /* Initialize iterator and associate with hash table */
    memset(&iter, 0, sizeof(iter));
    iter.ht = &challenge_table; // Associate with hash table

    /* Start walking the hash table */
    rhashtable_walk_start(&iter);
    while ((entry = rhashtable_walk_next(&iter))) {
        rhashtable_remove_fast(&challenge_table, &entry->node, challenge_params);
        kfree(entry);
    }
    /* Stop walking */
    rhashtable_walk_stop(&iter);

    /* Destroy the hash table */
    rhashtable_destroy(&challenge_table);

    printk(KERN_INFO "ICMP Authenticator: Module unloaded\n");
}

module_init(icmp_authenticator_init);
module_exit(icmp_authenticator_exit);
