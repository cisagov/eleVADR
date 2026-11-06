@load base/frameworks/logging

module EleVADRARP;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log;
        sender_ip: addr &log;
        sender_mac: string &log;
        target_ip: addr &log;
        target_mac: string &log;
        operation: string &log;
    };
}

event zeek_init() &priority=5
    {
    # Zeek exposes an ARP packet analyzer, but ARP event generation is not
    # guaranteed to be enabled by the stock policy set in every release.
    # Register EtherType 0x0806 explicitly so eleVADR can consume ARP identity
    # observations from raw PCAPs without relying on site-local Zeek policy.
    PacketAnalyzer::register_packet_analyzer(
        PacketAnalyzer::ANALYZER_ETHERNET,
        0x0806,
        PacketAnalyzer::ANALYZER_ARP
    );

    Log::create_stream(EleVADRARP::LOG, [$columns=Info, $path="arp"]);
    }

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    Log::write(EleVADRARP::LOG, [
        $ts=network_time(),
        $sender_ip=SPA,
        $sender_mac=SHA,
        $target_ip=TPA,
        $target_mac=THA,
        $operation="request"
    ]);
    }

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string)
    {
    Log::write(EleVADRARP::LOG, [
        $ts=network_time(),
        $sender_ip=SPA,
        $sender_mac=SHA,
        $target_ip=TPA,
        $target_mac=THA,
        $operation="reply"
    ]);
    }
