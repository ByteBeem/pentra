/// Maps port numbers to (service_name, description) tuples.
/// This is a curated subset of IANA assignments + common services.
pub fn lookup(port: u16, proto: &str) -> Option<&'static str> {
    match (port, proto) {
        // ── Web ──────────────────────────────────────────────────────────
        (80, "tcp")   => Some("http"),
        (443, "tcp")  => Some("https"),
        (8080, "tcp") => Some("http-alt"),
        (8443, "tcp") => Some("https-alt"),
        (8000, "tcp") => Some("http-alt"),
        (8888, "tcp") => Some("http-alt"),
        (3000, "tcp") => Some("http-dev"),
        (3001, "tcp") => Some("grafana"),
        (4000, "tcp") => Some("http-dev"),
        (5000, "tcp") => Some("http-dev"),
        (9090, "tcp") => Some("http-proxy"),
        (9091, "tcp") => Some("prometheus"),

        // ── Remote Access ────────────────────────────────────────────────
        (22, "tcp")   => Some("ssh"),
        (23, "tcp")   => Some("telnet"),
        (3389, "tcp") => Some("rdp"),
        (5900, "tcp") => Some("vnc"),
        (5901, "tcp") => Some("vnc-1"),
        (5902, "tcp") => Some("vnc-2"),
        (4899, "tcp") => Some("radmin"),

        // ── Mail ─────────────────────────────────────────────────────────
        (25, "tcp")   => Some("smtp"),
        (465, "tcp")  => Some("smtps"),
        (587, "tcp")  => Some("submission"),
        (110, "tcp")  => Some("pop3"),
        (995, "tcp")  => Some("pop3s"),
        (143, "tcp")  => Some("imap"),
        (993, "tcp")  => Some("imaps"),

        // ── DNS ──────────────────────────────────────────────────────────
        (53, "tcp")   => Some("dns"),
        (53, "udp")   => Some("dns"),
        (853, "tcp")  => Some("dns-over-tls"),

        // ── File Transfer ────────────────────────────────────────────────
        (20, "tcp")   => Some("ftp-data"),
        (21, "tcp")   => Some("ftp"),
        (69, "udp")   => Some("tftp"),
        (115, "tcp")  => Some("sftp"),
        (445, "tcp")  => Some("smb"),
        (139, "tcp")  => Some("netbios-ssn"),
        (137, "udp")  => Some("netbios-ns"),
        (138, "udp")  => Some("netbios-dgm"),
        (2049, "tcp") => Some("nfs"),
        (2049, "udp") => Some("nfs"),

        // ── Databases ────────────────────────────────────────────────────
        (3306, "tcp") => Some("mysql"),
        (5432, "tcp") => Some("postgresql"),
        (1433, "tcp") => Some("mssql"),
        (1521, "tcp") => Some("oracle"),
        (27017, "tcp")=> Some("mongodb"),
        (6379, "tcp") => Some("redis"),
        (11211, "tcp")=> Some("memcached"),
        (11211, "udp")=> Some("memcached"),
        (5984, "tcp") => Some("couchdb"),
        (9200, "tcp") => Some("elasticsearch"),
        (9300, "tcp") => Some("elasticsearch-cluster"),
        (7474, "tcp") => Some("neo4j"),
        (8529, "tcp") => Some("arangodb"),
        (2181, "tcp") => Some("zookeeper"),
        (9092, "tcp") => Some("kafka"),

        // ── Infra / DevOps ───────────────────────────────────────────────
        (2375, "tcp") => Some("docker"),
        (2376, "tcp") => Some("docker-tls"),
        (6443, "tcp") => Some("kubernetes-api"),
        (10250, "tcp")=> Some("kubelet"),
        (8500, "tcp") => Some("consul"),
        (8600, "tcp") => Some("consul-dns"),
        (4001, "tcp") => Some("etcd"),
        (2379, "tcp") => Some("etcd"),
        (2380, "tcp") => Some("etcd-peer"),


        // ── Message Queues ───────────────────────────────────────────────
        (5672, "tcp") => Some("amqp"),
        (5671, "tcp") => Some("amqps"),
        (61616, "tcp")=> Some("activemq"),
        (1883, "tcp") => Some("mqtt"),
        (8883, "tcp") => Some("mqtts"),

        // ── Security / Auth ──────────────────────────────────────────────
        (389, "tcp")  => Some("ldap"),
        (636, "tcp")  => Some("ldaps"),
        (88, "tcp")   => Some("kerberos"),
        (88, "udp")   => Some("kerberos"),
        (464, "tcp")  => Some("kerberos-change-pw"),
        (500, "udp")  => Some("isakmp"),
        (4500, "udp") => Some("ipsec-nat"),
        (1194, "udp") => Some("openvpn"),
        (51820, "udp")=> Some("wireguard"),

        // ── Network Services ─────────────────────────────────────────────
        (67, "udp")   => Some("dhcp-server"),
        (68, "udp")   => Some("dhcp-client"),
        (123, "udp")  => Some("ntp"),
        (161, "udp")  => Some("snmp"),
        (162, "udp")  => Some("snmp-trap"),
        (179, "tcp")  => Some("bgp"),
        (520, "udp")  => Some("rip"),
        (1812, "udp") => Some("radius"),
        (5353, "udp") => Some("mdns"),

        // ── VoIP ─────────────────────────────────────────────────────────
        (5060, "tcp") => Some("sip"),
        (5060, "udp") => Some("sip"),
        (5061, "tcp") => Some("sips"),
        (16384..=32767, "udp") => Some("rtp-candidate"),

        // ── Other Common ─────────────────────────────────────────────────
        (111, "tcp")  => Some("rpcbind"),
        (111, "udp")  => Some("rpcbind"),
        (512, "tcp")  => Some("exec"),
        (513, "tcp")  => Some("login"),
        (514, "tcp")  => Some("shell"),
        (514, "udp")  => Some("syslog"),
        (873, "tcp")  => Some("rsync"),
        (1723, "tcp") => Some("pptp"),
        (3128, "tcp") => Some("squid-proxy"),
        (8118, "tcp") => Some("privoxy"),
        (9050, "tcp") => Some("tor-socks"),
        (6667, "tcp") => Some("irc"),
        (6697, "tcp") => Some("ircs"),
        (25565, "tcp")=> Some("minecraft"),
        (27015, "tcp")=> Some("steam"),

        _ => None,
    }
}

/// Named port sets for convenient scanning
pub fn named_set(name: &str) -> Option<Vec<u16>> {
    match name {
        "web" => Some(vec![
            80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9090,
            8008, 8081, 8082, 8180, 8888, 10443,
        ]),
        "db" => Some(vec![
            1433, 1521, 2181, 2379, 3306, 5432, 5984, 6379,
            7474, 8529, 9200, 9300, 11211, 27017,
        ]),
        "mail" => Some(vec![25, 110, 143, 465, 587, 993, 995]),
        "smb" => Some(vec![135, 137, 138, 139, 445]),
        "voip" => Some(vec![5060, 5061, 4569, 2000]),
        "infra" => Some(vec![
            2375, 2376, 2379, 2380, 4001, 6443, 8500, 9090, 10250,
        ]),
        _ => None,
    }
}

pub const TOP_100: &[u16] = &[
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
    113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
    513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
    1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
    5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
    5900, 6000, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
    9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
];
