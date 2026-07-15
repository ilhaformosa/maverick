#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
    use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
    use smoltcp::phy::{
        ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
    };
    use smoltcp::socket::{tcp, udp};
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpEndpoint};

    const MTU: usize = 1500;
    const DEVICE_QUEUE_LIMIT: usize = 4;
    const TCP_BUFFER_SIZE: usize = 4096;
    const UDP_BUFFER_SIZE: usize = 4096;
    const UDP_MESSAGE_LIMIT: usize = 4;
    const CLIENT_SEQUENCE: u32 = 100;

    #[derive(Clone, Copy, Debug)]
    enum Family {
        V4,
        V6,
    }

    impl Family {
        fn app(self) -> SocketAddr {
            match self {
                Self::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 41_000),
                Self::V6 => SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
                    41_000,
                ),
            }
        }

        fn target(self) -> SocketAddr {
            match self {
                Self::V4 => SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 443),
                Self::V6 => SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
                    443,
                ),
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    enum AdmissionError {
        Empty,
        MtuExceeded,
        QueueFull,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FlowAdmissionError {
        LimitReached,
    }

    struct BoundedTcpFlows {
        limit: usize,
        handles: Vec<SocketHandle>,
    }

    impl BoundedTcpFlows {
        fn new(limit: usize) -> Self {
            Self {
                limit,
                handles: Vec::with_capacity(limit),
            }
        }

        fn admit_listener(
            &mut self,
            harness: &mut Harness,
            target: SocketAddr,
        ) -> Result<SocketHandle, FlowAdmissionError> {
            if self.handles.len() >= self.limit {
                return Err(FlowAdmissionError::LimitReached);
            }
            let handle = harness.add_tcp_listener(target);
            self.handles.push(handle);
            Ok(handle)
        }

        fn len(&self) -> usize {
            self.handles.len()
        }

        fn release_all(&mut self, harness: &mut Harness) {
            for handle in self.handles.drain(..) {
                harness.sockets.get_mut::<tcp::Socket>(handle).abort();
                harness.sockets.remove(handle);
            }
        }
    }

    struct BoundedDevice {
        incoming: VecDeque<Vec<u8>>,
        outgoing: VecDeque<Vec<u8>>,
        queue_limit: usize,
        mtu: usize,
        peak_incoming: usize,
        peak_outgoing: usize,
    }

    impl BoundedDevice {
        fn new(mtu: usize, queue_limit: usize) -> Self {
            Self {
                incoming: VecDeque::with_capacity(queue_limit),
                outgoing: VecDeque::with_capacity(queue_limit),
                queue_limit,
                mtu,
                peak_incoming: 0,
                peak_outgoing: 0,
            }
        }

        fn admit(&mut self, packet: Vec<u8>) -> Result<(), AdmissionError> {
            if packet.is_empty() {
                return Err(AdmissionError::Empty);
            }
            if packet.len() > self.mtu {
                return Err(AdmissionError::MtuExceeded);
            }
            if self.incoming.len() >= self.queue_limit {
                return Err(AdmissionError::QueueFull);
            }
            self.incoming.push_back(packet);
            self.peak_incoming = self.peak_incoming.max(self.incoming.len());
            Ok(())
        }

        fn admit_malformed(&mut self, packet: Vec<u8>) -> Result<(), AdmissionError> {
            if self.incoming.len() >= self.queue_limit {
                return Err(AdmissionError::QueueFull);
            }
            self.incoming.push_back(packet);
            self.peak_incoming = self.peak_incoming.max(self.incoming.len());
            Ok(())
        }

        fn take_outgoing(&mut self) -> Option<Vec<u8>> {
            self.outgoing.pop_front()
        }

        fn clear_outgoing(&mut self) {
            self.outgoing.clear();
        }
    }

    struct DeviceRx(Vec<u8>);

    struct DeviceTx<'a> {
        outgoing: &'a mut VecDeque<Vec<u8>>,
        peak_outgoing: &'a mut usize,
    }

    impl RxToken for DeviceRx {
        fn consume<R, F>(self, f: F) -> R
        where
            F: FnOnce(&[u8]) -> R,
        {
            f(&self.0)
        }
    }

    impl TxToken for DeviceTx<'_> {
        fn consume<R, F>(self, len: usize, f: F) -> R
        where
            F: FnOnce(&mut [u8]) -> R,
        {
            let mut packet = vec![0; len];
            let result = f(&mut packet);
            self.outgoing.push_back(packet);
            *self.peak_outgoing = (*self.peak_outgoing).max(self.outgoing.len());
            result
        }
    }

    impl Device for BoundedDevice {
        type RxToken<'a> = DeviceRx;
        type TxToken<'a> = DeviceTx<'a>;

        fn receive(
            &mut self,
            _timestamp: Instant,
        ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
            if self.outgoing.len() >= self.queue_limit {
                return None;
            }
            let packet = self.incoming.pop_front()?;
            Some((
                DeviceRx(packet),
                DeviceTx {
                    outgoing: &mut self.outgoing,
                    peak_outgoing: &mut self.peak_outgoing,
                },
            ))
        }

        fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
            if self.outgoing.len() >= self.queue_limit {
                return None;
            }
            Some(DeviceTx {
                outgoing: &mut self.outgoing,
                peak_outgoing: &mut self.peak_outgoing,
            })
        }

        fn capabilities(&self) -> DeviceCapabilities {
            let mut capabilities = DeviceCapabilities::default();
            capabilities.medium = Medium::Ip;
            capabilities.max_transmission_unit = self.mtu;
            capabilities.checksum = ChecksumCapabilities::default();
            capabilities
        }
    }

    struct Harness {
        interface: Interface,
        device: BoundedDevice,
        sockets: SocketSet<'static>,
        now_ms: i64,
    }

    impl Harness {
        fn new() -> Self {
            let mut device = BoundedDevice::new(MTU, DEVICE_QUEUE_LIMIT);
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 7;
            let mut interface = Interface::new(config, &mut device, Instant::ZERO);
            interface.set_any_ip(true);
            Self {
                interface,
                device,
                sockets: SocketSet::new(Vec::new()),
                now_ms: 0,
            }
        }

        fn add_tcp_listener(&mut self, endpoint: SocketAddr) -> SocketHandle {
            let rx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
            let tx = tcp::SocketBuffer::new(vec![0; TCP_BUFFER_SIZE]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(10)));
            socket.listen(smol_endpoint(endpoint)).unwrap();
            self.sockets.add(socket)
        }

        fn add_udp_socket(&mut self, endpoint: SocketAddr) -> SocketHandle {
            let rx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_MESSAGE_LIMIT],
                vec![0; UDP_BUFFER_SIZE],
            );
            let tx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_MESSAGE_LIMIT],
                vec![0; UDP_BUFFER_SIZE],
            );
            let mut socket = udp::Socket::new(rx, tx);
            socket.bind(smol_endpoint(endpoint)).unwrap();
            self.sockets.add(socket)
        }

        fn poll_after(&mut self, elapsed_ms: i64) {
            self.now_ms += elapsed_ms;
            self.interface.poll(
                Instant::from_millis(self.now_ms),
                &mut self.device,
                &mut self.sockets,
            );
        }

        fn admit_and_poll(&mut self, packet: Vec<u8>) {
            self.device.admit(packet).unwrap();
            self.poll_after(1);
        }
    }

    struct EstablishedTcp {
        harness: Harness,
        handle: SocketHandle,
        family: Family,
        server_sequence: u32,
    }

    impl EstablishedTcp {
        fn new(family: Family) -> Self {
            let mut harness = Harness::new();
            let handle = harness.add_tcp_listener(family.target());
            harness.admit_and_poll(tcp_packet(
                family.app(),
                family.target(),
                CLIENT_SEQUENCE,
                None,
                TcpFlags::SYN,
                &[],
            ));
            let syn_ack = harness.device.take_outgoing().expect("SYN-ACK");
            let (header, payload) = parsed_tcp(&syn_ack);
            assert!(header.syn && header.ack);
            assert!(payload.is_empty());
            assert_eq!(header.acknowledgment_number, CLIENT_SEQUENCE + 1);

            harness.admit_and_poll(tcp_packet(
                family.app(),
                family.target(),
                CLIENT_SEQUENCE + 1,
                Some(header.sequence_number + 1),
                TcpFlags::NONE,
                &[],
            ));
            assert_eq!(
                harness.sockets.get::<tcp::Socket>(handle).state(),
                tcp::State::Established
            );
            harness.device.clear_outgoing();

            Self {
                harness,
                handle,
                family,
                server_sequence: header.sequence_number,
            }
        }

        fn app_to_engine(&mut self, payload: &[u8]) -> Vec<u8> {
            self.harness.admit_and_poll(tcp_packet(
                self.family.app(),
                self.family.target(),
                CLIENT_SEQUENCE + 1,
                Some(self.server_sequence + 1),
                TcpFlags::PSH,
                payload,
            ));
            let socket = self.harness.sockets.get_mut::<tcp::Socket>(self.handle);
            let mut received = vec![0; payload.len()];
            let count = socket.recv_slice(&mut received).unwrap();
            received.truncate(count);
            received
        }

        fn engine_to_app(&mut self, payload: &[u8]) -> Vec<u8> {
            self.harness
                .sockets
                .get_mut::<tcp::Socket>(self.handle)
                .send_slice(payload)
                .unwrap();
            self.harness.poll_after(1);
            while let Some(packet) = self.harness.device.take_outgoing() {
                let (_, packet_payload) = parsed_tcp(&packet);
                if !packet_payload.is_empty() {
                    return packet_payload;
                }
            }
            panic!("missing TCP payload");
        }
    }

    #[derive(Clone, Copy)]
    struct TcpFlags {
        syn: bool,
        fin: bool,
        rst: bool,
        psh: bool,
    }

    impl TcpFlags {
        const NONE: Self = Self {
            syn: false,
            fin: false,
            rst: false,
            psh: false,
        };
        const SYN: Self = Self {
            syn: true,
            ..Self::NONE
        };
        const PSH: Self = Self {
            psh: true,
            ..Self::NONE
        };
        const FIN: Self = Self {
            fin: true,
            ..Self::NONE
        };
        const RST: Self = Self {
            rst: true,
            ..Self::NONE
        };
    }

    fn tcp_packet(
        source: SocketAddr,
        destination: SocketAddr,
        sequence: u32,
        acknowledgment: Option<u32>,
        flags: TcpFlags,
        payload: &[u8],
    ) -> Vec<u8> {
        let source_port = source.port();
        let destination_port = destination.port();
        let mut builder = match (source.ip(), destination.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => PacketBuilder::ipv4(
                source.octets(),
                destination.octets(),
                64,
            )
            .tcp(source_port, destination_port, sequence, 32_768),
            (IpAddr::V6(source), IpAddr::V6(destination)) => PacketBuilder::ipv6(
                source.octets(),
                destination.octets(),
                64,
            )
            .tcp(source_port, destination_port, sequence, 32_768),
            _ => panic!("mixed address families"),
        };
        if flags.syn {
            builder = builder.syn();
        }
        if flags.fin {
            builder = builder.fin();
        }
        if flags.rst {
            builder = builder.rst();
        }
        if flags.psh {
            builder = builder.psh();
        }
        if let Some(acknowledgment) = acknowledgment {
            builder = builder.ack(acknowledgment);
        }
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();
        packet
    }

    fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let source_port = source.port();
        let destination_port = destination.port();
        let builder = match (source.ip(), destination.ip()) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                PacketBuilder::ipv4(source.octets(), destination.octets(), 64)
                    .udp(source_port, destination_port)
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                PacketBuilder::ipv6(source.octets(), destination.octets(), 64)
                    .udp(source_port, destination_port)
            }
            _ => panic!("mixed address families"),
        };
        let mut packet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut packet, payload).unwrap();
        packet
    }

    fn parsed_tcp(packet: &[u8]) -> (etherparse::TcpHeader, Vec<u8>) {
        let sliced = SlicedPacket::from_ip(packet).unwrap();
        match sliced.transport.unwrap() {
            TransportSlice::Tcp(tcp) => (tcp.to_header(), tcp.payload().to_vec()),
            _ => panic!("not TCP"),
        }
    }

    fn parsed_udp(packet: &[u8]) -> (etherparse::UdpHeader, Vec<u8>) {
        let sliced = SlicedPacket::from_ip(packet).unwrap();
        match sliced.transport.unwrap() {
            TransportSlice::Udp(udp) => (udp.to_header(), udp.payload().to_vec()),
            _ => panic!("not UDP"),
        }
    }

    fn smol_endpoint(endpoint: SocketAddr) -> IpEndpoint {
        IpEndpoint::new(IpAddress::from(endpoint.ip()), endpoint.port())
    }

    fn assert_tcp_round_trip(family: Family) {
        let mut flow = EstablishedTcp::new(family);
        assert_eq!(flow.app_to_engine(b"request"), b"request");
        assert_eq!(flow.engine_to_app(b"response"), b"response");
        let socket = flow.harness.sockets.get::<tcp::Socket>(flow.handle);
        assert_eq!(
            socket.local_endpoint(),
            Some(smol_endpoint(family.target()))
        );
        assert_eq!(socket.remote_endpoint(), Some(smol_endpoint(family.app())));
    }

    fn assert_udp_round_trip(family: Family) {
        let mut harness = Harness::new();
        let handle = harness.add_udp_socket(family.target());
        harness.admit_and_poll(udp_packet(family.app(), family.target(), b"query"));

        let socket = harness.sockets.get_mut::<udp::Socket>(handle);
        let (payload, metadata) = socket.recv().unwrap();
        assert_eq!(payload, b"query");
        assert_eq!(metadata.endpoint, smol_endpoint(family.app()));
        assert_eq!(
            metadata.local_address,
            Some(IpAddress::from(family.target().ip()))
        );
        socket
            .send_slice(
                b"answer",
                udp::UdpMetadata {
                    endpoint: smol_endpoint(family.app()),
                    local_address: Some(IpAddress::from(family.target().ip())),
                    meta: Default::default(),
                },
            )
            .unwrap();
        harness.poll_after(1);

        let packet = harness.device.take_outgoing().expect("UDP response");
        let (header, payload) = parsed_udp(&packet);
        assert_eq!(header.source_port, family.target().port());
        assert_eq!(header.destination_port, family.app().port());
        assert_eq!(payload, b"answer");
    }

    #[test]
    fn pkt_01_tcp_01_ipv4_tcp_round_trip() {
        assert_tcp_round_trip(Family::V4);
    }

    #[test]
    fn pkt_02_tcp_02_ipv6_tcp_round_trip() {
        assert_tcp_round_trip(Family::V6);
    }

    #[test]
    fn pkt_03_udp_01_ipv4_udp_round_trip() {
        assert_udp_round_trip(Family::V4);
    }

    #[test]
    fn pkt_04_udp_02_ipv6_udp_round_trip() {
        assert_udp_round_trip(Family::V6);
    }

    #[test]
    fn pkt_05_pkt_06_malformed_packets_do_not_create_state() {
        let mut harness = Harness::new();
        let handle = harness.add_tcp_listener(Family::V4.target());
        for length in 0..40 {
            harness.device.admit_malformed(vec![0; length]).unwrap();
            harness.poll_after(1);
        }
        assert_eq!(
            harness.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Listen
        );
        assert!(harness.device.outgoing.is_empty());
        assert!(harness.device.peak_incoming <= DEVICE_QUEUE_LIMIT);
        assert!(harness.device.peak_outgoing <= DEVICE_QUEUE_LIMIT);
    }

    #[test]
    fn pkt_07_invalid_tcp_checksum_is_rejected() {
        let mut harness = Harness::new();
        let handle = harness.add_tcp_listener(Family::V4.target());
        let mut packet = tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        );
        let checksum_index = 20 + 16;
        packet[checksum_index] ^= 0x80;
        harness.admit_and_poll(packet);
        assert_eq!(
            harness.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Listen
        );
        assert!(harness.device.outgoing.is_empty());
    }

    #[test]
    fn pkt_09_device_admission_rejects_empty_oversized_and_saturated_input() {
        let mut device = BoundedDevice::new(MTU, DEVICE_QUEUE_LIMIT);
        assert_eq!(device.admit(Vec::new()), Err(AdmissionError::Empty));
        assert_eq!(
            device.admit(vec![0; MTU + 1]),
            Err(AdmissionError::MtuExceeded)
        );
        for _ in 0..DEVICE_QUEUE_LIMIT {
            device.admit(vec![0; 20]).unwrap();
        }
        assert_eq!(device.admit(vec![0; 20]), Err(AdmissionError::QueueFull));
        assert_eq!(device.peak_incoming, DEVICE_QUEUE_LIMIT);
    }

    #[test]
    fn tcp_07_unmatched_syn_gets_reset_without_allocating_a_flow() {
        let mut harness = Harness::new();
        harness.admit_and_poll(tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ));
        let packet = harness.device.take_outgoing().expect("RST");
        let (header, payload) = parsed_tcp(&packet);
        assert!(header.rst && header.ack);
        assert!(payload.is_empty());
        assert_eq!(harness.sockets.iter().count(), 0);
    }

    #[test]
    fn tcp_10_dropped_syn_ack_is_retransmitted() {
        let mut harness = Harness::new();
        let handle = harness.add_tcp_listener(Family::V4.target());
        harness.admit_and_poll(tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE,
            None,
            TcpFlags::SYN,
            &[],
        ));
        harness.device.clear_outgoing();

        let mut retransmitted = false;
        for _ in 0..60 {
            harness.poll_after(100);
            if let Some(packet) = harness.device.take_outgoing() {
                let (header, _) = parsed_tcp(&packet);
                if header.syn && header.ack {
                    retransmitted = true;
                    break;
                }
            }
        }
        assert!(retransmitted);
        assert_eq!(
            harness.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::SynReceived
        );
    }

    #[test]
    fn tcp_03_local_half_close_still_allows_remote_data() {
        let mut flow = EstablishedTcp::new(Family::V4);
        flow.harness.admit_and_poll(tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE + 1,
            Some(flow.server_sequence + 1),
            TcpFlags::FIN,
            &[],
        ));
        assert_eq!(
            flow.harness.sockets.get::<tcp::Socket>(flow.handle).state(),
            tcp::State::CloseWait
        );
        flow.harness.device.clear_outgoing();
        assert_eq!(flow.engine_to_app(b"after-fin"), b"after-fin");
        flow.harness
            .sockets
            .get_mut::<tcp::Socket>(flow.handle)
            .close();
        flow.harness.poll_after(1);
        assert!(flow
            .harness
            .device
            .outgoing
            .iter()
            .any(|packet| parsed_tcp(packet).0.fin));
    }

    #[test]
    fn tcp_05_peer_reset_releases_socket_state() {
        let mut flow = EstablishedTcp::new(Family::V4);
        flow.harness.admit_and_poll(tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE + 1,
            Some(flow.server_sequence + 1),
            TcpFlags::RST,
            &[],
        ));
        assert_eq!(
            flow.harness.sockets.get::<tcp::Socket>(flow.handle).state(),
            tcp::State::Closed
        );
    }

    #[test]
    fn tcp_06_engine_abort_emits_reset() {
        let mut flow = EstablishedTcp::new(Family::V4);
        flow.harness
            .sockets
            .get_mut::<tcp::Socket>(flow.handle)
            .abort();
        flow.harness.poll_after(1);
        assert!(flow
            .harness
            .device
            .outgoing
            .iter()
            .any(|packet| parsed_tcp(packet).0.rst));
    }

    #[test]
    fn tcp_09_idle_timeout_releases_socket() {
        let mut flow = EstablishedTcp::new(Family::V4);
        flow.harness.poll_after(10_001);
        assert_eq!(
            flow.harness.sockets.get::<tcp::Socket>(flow.handle).state(),
            tcp::State::Closed
        );
    }

    #[test]
    fn tcp_11_reordered_segments_deliver_exact_payload() {
        let mut flow = EstablishedTcp::new(Family::V4);
        flow.harness.admit_and_poll(tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE + 6,
            Some(flow.server_sequence + 1),
            TcpFlags::PSH,
            b"world",
        ));
        flow.harness.device.clear_outgoing();
        flow.harness.admit_and_poll(tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE + 1,
            Some(flow.server_sequence + 1),
            TcpFlags::PSH,
            b"hello",
        ));
        let socket = flow.harness.sockets.get_mut::<tcp::Socket>(flow.handle);
        let mut received = [0; 10];
        assert_eq!(socket.recv_slice(&mut received).unwrap(), received.len());
        assert_eq!(&received, b"helloworld");
    }

    #[test]
    fn tcp_12_duplicate_segment_is_delivered_once() {
        let mut flow = EstablishedTcp::new(Family::V4);
        let packet = tcp_packet(
            Family::V4.app(),
            Family::V4.target(),
            CLIENT_SEQUENCE + 1,
            Some(flow.server_sequence + 1),
            TcpFlags::PSH,
            b"hello",
        );
        flow.harness.admit_and_poll(packet.clone());
        flow.harness.device.clear_outgoing();
        flow.harness.admit_and_poll(packet);
        let socket = flow.harness.sockets.get_mut::<tcp::Socket>(flow.handle);
        assert_eq!(socket.recv_queue(), 5);
        let mut received = [0; 5];
        assert_eq!(socket.recv_slice(&mut received).unwrap(), received.len());
        assert_eq!(&received, b"hello");
    }

    #[test]
    fn tcp_14_receive_buffer_applies_fixed_backpressure() {
        let mut flow = EstablishedTcp::new(Family::V4);
        let segment = vec![7; 1024];
        for index in 0..4 {
            flow.harness.admit_and_poll(tcp_packet(
                Family::V4.app(),
                Family::V4.target(),
                CLIENT_SEQUENCE + 1 + index * segment.len() as u32,
                Some(flow.server_sequence + 1),
                TcpFlags::PSH,
                &segment,
            ));
            flow.harness.device.clear_outgoing();
        }
        let socket = flow.harness.sockets.get::<tcp::Socket>(flow.handle);
        assert_eq!(socket.recv_queue(), TCP_BUFFER_SIZE);
        assert_eq!(socket.recv_capacity(), TCP_BUFFER_SIZE);
        assert!(!socket.can_recv() || socket.recv_queue() <= TCP_BUFFER_SIZE);
        assert!(flow.harness.device.peak_outgoing <= DEVICE_QUEUE_LIMIT);
    }

    #[test]
    fn pkt_10_malformed_burst_keeps_queues_and_state_bounded() {
        let mut harness = Harness::new();
        let handle = harness.add_tcp_listener(Family::V4.target());
        for index in 0..4096 {
            let length = index % 40;
            harness.device.admit_malformed(vec![0; length]).unwrap();
            harness.poll_after(1);
        }
        assert_eq!(
            harness.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::Listen
        );
        assert!(harness.device.peak_incoming <= DEVICE_QUEUE_LIMIT);
        assert!(harness.device.peak_outgoing <= DEVICE_QUEUE_LIMIT);
    }

    #[test]
    fn udp_11_queue_saturation_is_bounded_and_drops_excess() {
        let mut harness = Harness::new();
        let handle = harness.add_udp_socket(Family::V4.target());
        for index in 0..UDP_MESSAGE_LIMIT + 1 {
            harness.admit_and_poll(udp_packet(
                SocketAddr::new(
                    Family::V4.app().ip(),
                    Family::V4.app().port() + index as u16,
                ),
                Family::V4.target(),
                &[index as u8],
            ));
        }
        let socket = harness.sockets.get_mut::<udp::Socket>(handle);
        assert_eq!(socket.recv_queue(), UDP_MESSAGE_LIMIT);
        assert_eq!(socket.packet_recv_capacity(), UDP_MESSAGE_LIMIT);
        for expected in 0..UDP_MESSAGE_LIMIT {
            let (payload, _) = socket.recv().unwrap();
            assert_eq!(payload, &[expected as u8]);
        }
        assert!(!socket.can_recv());
    }

    #[test]
    fn res_03_res_04_res_05_one_above_flow_limit_is_rejected() {
        const FLOW_LIMIT: usize = 100;
        let started = std::time::Instant::now();
        let mut harness = Harness::new();
        let mut flows = BoundedTcpFlows::new(FLOW_LIMIT);

        for index in 0..FLOW_LIMIT {
            let app = SocketAddr::new(
                Family::V4.app().ip(),
                Family::V4.app().port() + index as u16,
            );
            let target = SocketAddr::new(Family::V4.target().ip(), 10_000 + index as u16);
            let handle = flows.admit_listener(&mut harness, target).unwrap();
            harness.admit_and_poll(tcp_packet(
                app,
                target,
                CLIENT_SEQUENCE + index as u32,
                None,
                TcpFlags::SYN,
                &[],
            ));
            let syn_ack = harness.device.take_outgoing().expect("SYN-ACK");
            let (header, _) = parsed_tcp(&syn_ack);
            harness.admit_and_poll(tcp_packet(
                app,
                target,
                CLIENT_SEQUENCE + index as u32 + 1,
                Some(header.sequence_number + 1),
                TcpFlags::NONE,
                &[],
            ));
            harness.device.clear_outgoing();
            assert_eq!(
                harness.sockets.get::<tcp::Socket>(handle).state(),
                tcp::State::Established
            );
        }

        assert_eq!(flows.len(), FLOW_LIMIT);
        let sockets_at_limit = harness.sockets.iter().count();
        let one_above_target = SocketAddr::new(Family::V4.target().ip(), 20_000);
        assert!(matches!(
            flows.admit_listener(&mut harness, one_above_target),
            Err(FlowAdmissionError::LimitReached)
        ));
        assert_eq!(flows.len(), FLOW_LIMIT);
        assert_eq!(harness.sockets.iter().count(), sockets_at_limit);

        flows.release_all(&mut harness);
        assert_eq!(harness.sockets.iter().count(), 0);
        assert!(harness.device.peak_incoming <= DEVICE_QUEUE_LIMIT);
        assert!(harness.device.peak_outgoing <= DEVICE_QUEUE_LIMIT);
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }
}
