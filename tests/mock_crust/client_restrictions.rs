// Copyright 2017 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use super::{MIN_SECTION_SIZE, TestClient, TestNode, create_connected_clients,
            create_connected_nodes, poll_all, poll_and_resend};
use maidsafe_utilities::SeededRng;
use mock_crust::utils::gen_immutable_data;
use rand::Rng;
<<<<<<< HEAD
use routing::{Authority, BootstrapConfig, Event, EventStream, FullId, ImmutableData,
              MAX_IMMUTABLE_DATA_SIZE_IN_BYTES, MessageId, Request};
use routing::mock_crust::Network;
use routing::rate_limiter_consts::{MAX_PARTS, SOFT_CAPACITY};
use std::time::Duration;
=======
use routing::{Authority, BootstrapConfig, Event, EventStream, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES,
              MessageId, PublicId, Request, XorName};
use routing::ignore_result::Ignore;
use routing::mock_crust::Network;
use routing::rate_limiter_consts::{CAPACITY, MAX_CLIENTS_PER_PROXY, RATE};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// Connects multiple clients to the same proxy node, expecting clients fail to connect after
/// reaching `MAX_CLIENTS_PER_PROXY`, and succeed again when a connected client drops out.
#[test]
fn multiple_clients_per_proxy() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, MAX_CLIENTS_PER_PROXY);

    let config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    clients.push(TestClient::new(&network, Some(config.clone()), None));
    poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[MAX_CLIENTS_PER_PROXY], Event::Terminate);

    clients.remove(MAX_CLIENTS_PER_PROXY);
    clients.remove(0);
    poll_all(&mut nodes, &mut clients);

    clients.push(TestClient::new(&network, Some(config.clone()), None));
    poll_all(&mut nodes, &mut clients);
    expect_next_event!(clients[MAX_CLIENTS_PER_PROXY - 1], Event::Connected);
}

// Sends the requests and verifies recipients if `rate_limiter` approves the request.
// Returns rejected requests' message id and its client's ip address.
fn rate_limiter_send_reqs(network: &Network<PublicId>,
                          nodes: &mut [TestNode],
                          clients: &mut [TestClient],
                          total_usage: &mut u64,
                          is_always_send: bool)
                          -> HashMap<MessageId, IpAddr> {
    let mut rng = network.new_rng();
    let data_id: XorName = rng.gen();
    let dst = Authority::NaeManager(data_id);

    let mut clients_sent = HashMap::new();
    for client in clients.iter_mut() {
        if is_always_send || rng.gen_weighted_bool(2) {
            let msg_id = MessageId::new();
            unwrap!(client.inner.get_idata(dst, data_id, msg_id));
            clients_sent.insert(msg_id, client.ip());
        }
    }
    trace!("clients_sent: {:?}", clients_sent);
    poll_all(nodes, clients);

    let mut request_received: HashMap<MessageId, usize> = HashMap::new();
    for node in nodes.iter_mut().filter(|n| n.is_recipient(&dst)) {
        while let Ok(event) = node.try_next_ev() {
            if let Event::Request {
                       request: Request::GetIData { msg_id: req_message_id, .. }, ..
                   } = event {
                let entry = request_received.entry(req_message_id).or_insert(0);
                *entry += 1;
            }
        }
    }
    trace!("request_received: {:?}", request_received);

    for (msg_id, count) in &request_received {
        assert_eq!(*count, MIN_SECTION_SIZE);
        unwrap!(clients_sent.remove(msg_id));
        *total_usage += MAX_IMMUTABLE_DATA_SIZE_IN_BYTES;
    }
    assert!(*total_usage <= CAPACITY);

    clients_sent
}

// Verifies the usage in rate_limiter. Also advances the fake clock.
fn rate_limiter_verify(rejected_reqs: &HashMap<MessageId, IpAddr>,
                       clients_usage: &BTreeMap<IpAddr, u64>,
                       total_usage: &mut u64,
                       per_client_cap: u64) {
    // `rejected_reqs` contains only the clients whose request got rejected.
    // Needs to confirm such rejection is valid. However, if it is the total usage reaching the
    // cap, the usage of each client could be much less than the cap.
    if (*total_usage + MAX_IMMUTABLE_DATA_SIZE_IN_BYTES) <= CAPACITY {
        for ip in rejected_reqs.values() {
            assert!((unwrap!(clients_usage.get(ip)) + MAX_IMMUTABLE_DATA_SIZE_IN_BYTES) >
                    per_client_cap);
        }
    }

    let leaky_rate = 2 * MAX_IMMUTABLE_DATA_SIZE_IN_BYTES;
    let wait_millis = (leaky_rate * 1000) / RATE as u64;
    FakeClock::advance_time(wait_millis);
    *total_usage = total_usage.saturating_sub(leaky_rate);
}

/// Connects multiple clients to the same proxy node and randomly sending get requests.
/// Expect some requests will be blocked due to the rate limit.
/// Expect the total capacity of the proxy will never be exceeded.
#[test]
fn rate_limit_proxy_max_clients() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, MAX_CLIENTS_PER_PROXY);

    let mut total_usage: u64 = 0;
    let per_client_cap = CAPACITY / MAX_CLIENTS_PER_PROXY as u64;
    for _ in 0..10 {
        let rejected_reqs =
            rate_limiter_send_reqs(&network, &mut nodes, &mut clients, &mut total_usage, false);

        let clients_usage = nodes[0].inner.get_clients_usage();
        assert!(clients_usage
                    .iter()
                    .all(|(_, usage)| *usage <= per_client_cap));

        rate_limiter_verify(&rejected_reqs,
                            &clients_usage,
                            &mut total_usage,
                            per_client_cap);
    }
}

/// Connects random number of clients to the same proxy node and sending get requests.
/// Expect some requests will be blocked due to the rate limit.
/// Expect the total capacity of the proxy will never be exceeded.
#[test]
fn rate_limit_proxy_random_clients() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut rng = network.new_rng();

    let mut clients = Vec::new();
    let mut total_usage: u64 = 0;
    for _ in 0..10 {
        if clients.len() <= 1 || (clients.len() < MAX_CLIENTS_PER_PROXY && rng.gen()) {
            let new_client_count = rng.gen_range(1, MAX_CLIENTS_PER_PROXY - clients.len() + 1);
            clients.append(&mut create_connected_clients(&network, &mut nodes, new_client_count));
        } else {
            for _ in 0..rng.gen_range(1, clients.len()) {
                let len = clients.len();
                clients.remove(rng.gen_range(0, len));
                poll_all(&mut nodes, &mut clients);
            }
        }

        let rejected_reqs =
            rate_limiter_send_reqs(&network, &mut nodes, &mut clients, &mut total_usage, true);

        // Due to the changing of number of live clients, it is not guaranteed that each client's
        // usage is below `per_client_cap` of the current iteration.
        let clients_usage = nodes[0].inner.get_clients_usage();

        let per_client_cap = CAPACITY / clients.len() as u64;
        rate_limiter_verify(&rejected_reqs,
                            &clients_usage,
                            &mut total_usage,
                            per_client_cap);
    }
}
>>>>>>> 46c2c3e... Turn off `unused_results` lint.

/// Connect a client to the network then send an invalid message.
/// Expect the client will be disconnected and banned;
#[test]
fn ban_malicious_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);
    let mut rng = network.new_rng();

    // Send a `Refresh` request from the client; should cause it to get banned.
<<<<<<< HEAD
    let _ = clients[0].inner.send_request(
        Authority::NaeManager(rng.gen()),
        Request::Refresh(vec![], MessageId::new()),
        2,
    );
    let _ = poll_all(&mut nodes, &mut clients);
=======
    clients[0]
        .inner
        .send_request(Authority::NaeManager(rng.gen()),
                      Request::Refresh(vec![], MessageId::new()),
                      2)
        .ignore();
    poll_all(&mut nodes, &mut clients);
>>>>>>> 46c2c3e... Turn off `unused_results` lint.
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);
    let banned_client_ips = nodes[0].inner.get_banned_client_ips();
    assert_eq!(banned_client_ips.len(), 1);
    let ip_addr = clients[0].ip();
    assert_eq!(unwrap!(banned_client_ips.into_iter().next()), ip_addr);

    clients.remove(0);
    poll_all(&mut nodes, &mut clients);

    // Connect a new client with the same ip address shall get rejected.
    let endpoint = network.gen_endpoint_with_ip(&ip_addr);
    let contact = nodes[0].handle.endpoint();
    let client = TestClient::new(
        &network,
        Some(BootstrapConfig::with_contacts(&[contact])),
        Some(endpoint),
    );
    clients.push(client);
    poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);
}

/// Connects two clients to the network using the same ip address and via the same proxy.
/// Expect only one client got connected.
#[test]
fn only_one_client_per_ip() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    // Connect a new client with the same ip address shall get rejected.
    let endpoint = network.gen_endpoint_with_ip(&clients[0].ip());
    let contact = nodes[0].handle.endpoint();
    let client = TestClient::new(
        &network,
        Some(BootstrapConfig::with_contacts(&[contact])),
        Some(endpoint),
    );
    clients.push(client);
    poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);
}

/// Reconnect a client (disconnected as network not having enough nodes) with the same id.
#[test]
fn reconnect_disconnected_client() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE - 1);

    let config = Some(BootstrapConfig::with_contacts(
        &[nodes[1].handle.endpoint()],
    ));
    let full_id = FullId::new();

    // Client will get rejected as network not having enough nodes.
    let mut clients =
        vec![
            TestClient::new_with_full_id(&network, config.clone(), None, full_id.clone()),
        ];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Terminate);

    let _ = clients.remove(0);
    let bootstrap_config = BootstrapConfig::with_contacts(&[nodes[0].handle.endpoint()]);
    nodes.push(
        TestNode::builder(&network)
            .bootstrap_config(bootstrap_config)
            .create(),
    );
    let _ = poll_all(&mut nodes, &mut clients);

    // Reconnecting the client (with same id) shall succeed.
    clients.push(TestClient::new_with_full_id(
        &network,
        config,
        None,
        full_id,
    ));
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Connected);
}

fn immutable_data_vec(rng: &mut SeededRng, count: u64) -> Vec<ImmutableData> {
    (0..count)
        .map(|_| {
            gen_immutable_data(rng, MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as usize)
        })
        .collect()
}

/// Confirming the number of user message parts being sent in case of exceeding limit.
#[test]
fn resend_parts_on_exceeding_limit() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);
    let mut clients = create_connected_clients(&network, &mut nodes, 1);

    let num_immutable_data =
        (SOFT_CAPACITY as f64 / MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as f64).ceil() as u64 + 1;

    let data_vec = immutable_data_vec(&mut rng, num_immutable_data);

    for data in data_vec {
        let msg_id = MessageId::new();
        let dst = Authority::NaeManager(*data.name());
        unwrap!(clients[0].inner.put_idata(dst, data, msg_id));
    }
    poll_and_resend(&mut nodes, &mut clients);

    let total_data_parts = num_immutable_data * MAX_PARTS as u64;
    // NOTE: this calculation is approximate and relies on some hardcoded knowledge about
    // the size of serialised user messages.
    let user_msg_header = 48;
    let part_size = (MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + user_msg_header) as f64 / MAX_PARTS as f64;
    let parts_allowed_first_time = (SOFT_CAPACITY as f64 / part_size) as u64;
    let parts_retried = total_data_parts - parts_allowed_first_time;

    let expect_sent_parts = total_data_parts + parts_retried;
    assert_eq!(
        clients[0].inner.get_user_msg_parts_count(),
        expect_sent_parts
    );

    // Node shall not receive any duplicated parts.
    let expect_rcv_parts = total_data_parts;
    for node in nodes.iter() {
        assert_eq!(node.inner.get_user_msg_parts_count(), expect_rcv_parts);
    }
}

/// User message expired.
#[test]
fn resend_over_load() {
    let network = Network::new(MIN_SECTION_SIZE, None);
    let mut rng = network.new_rng();
    let mut nodes = create_connected_nodes(&network, MIN_SECTION_SIZE);

    let config = Some(BootstrapConfig::with_contacts(
        &[nodes[0].handle.endpoint()],
    ));
    let mut clients =
        vec![
            TestClient::new_with_expire_duration(&network, config, None, Duration::from_secs(10)),
        ];
    let _ = poll_all(&mut nodes, &mut clients);
    expect_next_event!(unwrap!(clients.last_mut()), Event::Connected);

    let num_immutable_data =
        (SOFT_CAPACITY as f64 / MAX_IMMUTABLE_DATA_SIZE_IN_BYTES as f64).ceil() as u64 + 1;

    let data_vec = immutable_data_vec(&mut rng, num_immutable_data);

    for data in data_vec {
        let msg_id = MessageId::new();
        let dst = Authority::NaeManager(*data.name());
        unwrap!(clients[0].inner.put_idata(dst, data, msg_id));
    }
    poll_and_resend(&mut nodes, &mut clients);

    let total_data_parts = num_immutable_data * MAX_PARTS as u64;
    // NOTE: this calculation is approximate and relies on some hardcoded knowledge about
    // the size of serialised user messages.
    let user_msg_header = 48;
    let part_size = (MAX_IMMUTABLE_DATA_SIZE_IN_BYTES + user_msg_header) as f64 / MAX_PARTS as f64;
    let parts_allowed_through = (SOFT_CAPACITY as f64 / part_size) as u64;

    // `poll_and_resend` advance clock by 20 seconds (`ACK_TIME_OUT`), hence the message is expired
    // when handling the timeout for re-sending parts.
    let expect_sent_parts = total_data_parts;
    assert_eq!(
        clients[0].inner.get_user_msg_parts_count(),
        expect_sent_parts
    );

    // Node shall not receive any re-sent parts.
    let expect_rcv_parts = parts_allowed_through;
    for node in nodes.iter() {
        assert_eq!(node.inner.get_user_msg_parts_count(), expect_rcv_parts);
    }

    // Routing client will not send any notification regarding this expiration.
    assert!(clients[0].inner.try_next_ev().is_err());
}
