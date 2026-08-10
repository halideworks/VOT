//! Rendezvous protocol: pairing serve and fetch by the package root.
//! Socket-independent; time is injected so expiry is testable.

mod key;
mod registrar;
mod service;
mod wire;

pub(crate) use key::*;
pub(crate) use registrar::*;
pub(crate) use service::*;
pub(crate) use wire::*;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::side_channel::address::from_service;

    use super::*;

    fn v4(text: &str) -> SocketAddr {
        text.parse().expect("an address")
    }

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    #[test]
    fn every_datagram_round_trips_and_no_reply_outgrows_its_request() {
        let key = [7; 32];
        let cases = [
            Datagram::Register { key },
            Datagram::Registered { key },
            Datagram::Resolve { key },
            Datagram::Resolved { key, serve: None },
            Datagram::Resolved {
                key,
                serve: Some(v4("192.0.2.1:4433")),
            },
            Datagram::Resolved {
                key,
                serve: Some("[2001:db8::1]:4433".parse().expect("an address")),
            },
            Datagram::Coming {
                key,
                fetch: v4("192.0.2.2:5000"),
            },
            Datagram::Warming,
        ];
        for datagram in cases {
            let wire = encode(&datagram);
            assert_eq!(wire[0], MAGIC);
            assert!(wire[0] < 0x40, "the magic can never open a QUIC packet");
            assert_eq!(decode(&wire), Some(datagram), "{datagram:?}");
        }
        let register = encode(&Datagram::Register { key }).len();
        let registered = encode(&Datagram::Registered { key }).len();
        assert_eq!(register, REQUEST_BYTES, "requests are padded to the bound");
        assert!(registered <= register);
        let resolve = encode(&Datagram::Resolve { key }).len();
        assert_eq!(resolve, REQUEST_BYTES);
        let resolved_widest = encode(&Datagram::Resolved {
            key,
            serve: Some("[2001:db8::1]:4433".parse().expect("an address")),
        })
        .len();
        assert_eq!(
            resolved_widest, resolve,
            "the request is padded to the widest reply and no further"
        );
        let coming_widest = encode(&Datagram::Coming {
            key,
            fetch: "[2001:db8::2]:4433".parse().expect("an address"),
        })
        .len();
        assert_eq!(
            coming_widest, register,
            "the notification is exactly the registration that earned it"
        );
    }

    #[test]
    fn what_is_not_a_datagram_is_nothing() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[MAGIC]), None);
        assert_eq!(decode(&[MAGIC, VERSION]), None);
        assert_eq!(decode(&[MAGIC, VERSION + 1, 1]), None, "another version");
        assert_eq!(decode(&[0x40, VERSION, 6]), None, "another protocol");
        assert_eq!(decode(&[MAGIC, VERSION, 9]), None, "another kind");
        let mut short = encode(&Datagram::Register { key: [7; 32] });
        short.pop();
        assert_eq!(decode(&short), None, "a truncated request");
        let mut dirty = encode(&Datagram::Resolve { key: [7; 32] });
        *dirty.last_mut().expect("padding exists") = 1;
        assert_eq!(decode(&dirty), None, "padding that carries bytes");
        let mut long = encode(&Datagram::Warming);
        long.push(0);
        assert_eq!(decode(&long), None, "trailing bytes");
    }

    #[test]
    fn an_address_slot_is_the_length_its_family_names() {
        let key = [7; 32];
        let widths = [
            Datagram::Resolved {
                key,
                serve: Some(v4("192.0.2.1:4433")),
            },
            Datagram::Resolved {
                key,
                serve: Some("[2001:db8::1]:4433".parse().expect("an address")),
            },
            Datagram::Coming {
                key,
                fetch: v4("192.0.2.2:5000"),
            },
            Datagram::Coming {
                key,
                fetch: "[2001:db8::2]:5000".parse().expect("an address"),
            },
        ];
        for datagram in widths {
            let mut over = encode(&datagram);
            over.push(0);
            assert_eq!(decode(&over), None, "a slot wider than its family");
            let mut under = encode(&datagram);
            under.pop();
            assert_eq!(decode(&under), None, "a slot narrower than its family");
        }
    }

    #[test]
    fn a_register_pairs_a_resolve_until_the_ttl_ends() {
        let mut pairings = Pairings::default();
        let key = [3; 32];
        let serve = v4("198.51.100.1:4433");
        let fetch = v4("203.0.113.9:60123");

        let miss = pairings.take(Datagram::Resolve { key }, fetch, 1_000);
        assert_eq!(miss.reply, Some(Datagram::Resolved { key, serve: None }));
        assert_eq!(miss.notify, None);

        let ack = pairings.take(Datagram::Register { key }, serve, 1_000);
        assert_eq!(ack.reply, Some(Datagram::Registered { key }));
        assert_eq!(ack.notify, None);

        let hit = pairings.take(Datagram::Resolve { key }, fetch, 2_000);
        assert_eq!(
            hit.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(serve)
            })
        );
        assert_eq!(hit.notify, Some((serve, Datagram::Coming { key, fetch })));

        let moved = v4("198.51.100.1:4500");
        pairings.take(Datagram::Register { key }, moved, 3_000);
        let refreshed = pairings.take(Datagram::Resolve { key }, fetch, 4_000);
        assert_eq!(
            refreshed.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(moved)
            })
        );

        let last = pairings.take(
            Datagram::Resolve { key },
            fetch,
            3_000 + REGISTRATION_TTL_MS - 1,
        );
        assert_eq!(
            last.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(moved)
            })
        );
        let expired = pairings.take(
            Datagram::Resolve { key },
            fetch,
            3_000 + REGISTRATION_TTL_MS,
        );
        assert_eq!(
            expired.reply,
            Some(Datagram::Resolved { key, serve: None }),
            "a registration is believed for its TTL and no longer"
        );

        assert_eq!(
            pairings.take(Datagram::Warming, fetch, 5_000),
            Answer::default()
        );
    }

    #[test]
    fn the_key_is_this_derivation_of_the_root_and_no_other() {
        let vectors = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../test-vectors/rendezvous/key.json"),
        )
        .expect("the committed key vectors");
        assert!(vectors.contains(KEY_CONTEXT), "the context is the vectors'");
        let mut cases = 0;
        for case in vectors.split("\"root_hex\": \"").skip(1) {
            let (root, rest) = case.split_once('"').expect("a root");
            let (_, key) = rest.split_once("\"key_hex\": \"").expect("a key");
            let (key, _) = key.split_once('"').expect("a key");
            let mut bytes = [0_u8; 32];
            for (byte, pair) in bytes.iter_mut().zip(root.as_bytes().chunks(2)) {
                *byte = u8::from_str_radix(std::str::from_utf8(pair).expect("hex"), 16)
                    .expect("a byte");
            }
            assert_eq!(hex(&key_of(&bytes)), key, "the vector for root {root}");
            cases += 1;
        }
        assert_eq!(cases, 4, "every committed case was checked");
        assert_ne!(
            key_of(&[1; 32]),
            key_of(&[0; 32]),
            "another root, another key"
        );
        assert_ne!(key_of(&[0; 32]), [0; 32], "the key is not the root");
    }

    #[test]
    fn a_service_is_itself_in_either_family() {
        let plain = v4("198.51.100.7:9000");
        let mapped = v4("[::ffff:198.51.100.7]:9000");
        let six = v4("[2001:db8::7]:9000");
        for (source, service) in [
            (plain, mapped),
            (mapped, plain),
            (plain, plain),
            (mapped, mapped),
            (six, six),
        ] {
            assert!(
                from_service(source, service),
                "{source} is {service} in the family that is really its own"
            );
        }
        for (source, service) in [
            (plain, v4("198.51.100.7:9001")),
            (plain, v4("198.51.100.8:9000")),
            (six, plain),
            (v4("[::ffff:198.51.100.8]:9000"), plain),
        ] {
            assert!(!from_service(source, service), "{source} is not {service}");
        }
    }

    #[test]
    fn a_dual_stack_serve_hears_the_service_it_was_configured_with() {
        // A serve bound to `[::]` reads an IPv4 service as `::ffff:a.b.c.d`,
        // which matches none of its configured addresses byte for byte.
        for (service, mapped, fetch) in [
            (
                v4("198.51.100.7:9000"),
                v4("[::ffff:198.51.100.7]:9000"),
                v4("203.0.113.9:60123"),
            ),
            (
                v4("127.0.0.1:9000"),
                v4("[::ffff:127.0.0.1]:9000"),
                v4("127.0.0.1:60123"),
            ),
        ] {
            let root = [9; 32];
            let key = key_of(&root);
            let mut registrar = Registrar::new(&root, &[service]);
            registrar.due(0);
            registrar.take(Datagram::Coming { key, fetch }, mapped);
            assert_eq!(
                registrar.due(1),
                vec![(fetch, Datagram::Warming)],
                "{mapped} is {service}, so the Coming it carried is owed a warming"
            );
        }
    }

    #[test]
    fn a_registrar_registers_on_its_cadence_and_warms_only_for_the_service() {
        let service = v4("198.51.100.7:9000");
        let fetch = v4("203.0.113.9:60123");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, &[service]);
        let key = key_of(&root);

        assert_eq!(
            registrar.due(0),
            vec![(service, Datagram::Register { key })],
            "a serve is findable from the moment it is serving"
        );
        assert_eq!(registrar.due(REGISTER_CADENCE_MS - 1), Vec::new());
        assert_eq!(
            registrar.due(REGISTER_CADENCE_MS),
            vec![(service, Datagram::Register { key })]
        );

        registrar.take(Datagram::Coming { key, fetch }, service);
        let now = REGISTER_CADENCE_MS;
        for pass in 0..WARMING_DATAGRAMS {
            assert_eq!(
                registrar.due(now),
                vec![(fetch, Datagram::Warming)],
                "pass {pass} owes exactly one warming"
            );
        }
        assert_eq!(registrar.due(now), Vec::new(), "and no more than it owes");

        let refused = [
            (Datagram::Coming { key, fetch }, fetch),
            (
                Datagram::Coming {
                    key: [0xAB; 32],
                    fetch,
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("0.0.0.0:5000"),
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("203.0.113.9:0"),
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("239.0.0.1:5000"),
                },
                service,
            ),
            (
                Datagram::Coming {
                    key,
                    fetch: v4("255.255.255.255:5000"),
                },
                service,
            ),
            (Datagram::Registered { key }, service),
            (Datagram::Resolve { key }, service),
            (Datagram::Warming, service),
        ];
        for (datagram, source) in refused {
            registrar.take(datagram, source);
            assert_eq!(
                registrar.due(now),
                Vec::new(),
                "{datagram:?} from {source} earned a warming"
            );
        }
    }

    #[test]
    fn only_what_could_be_an_observed_mapping_is_warmed() {
        let far = v4("198.51.100.7:9000");
        let near = v4("127.0.0.1:9000");
        assert!(warmable(v4("203.0.113.9:60123"), far));
        assert!(warmable(
            "[2001:db8::2]:60123".parse().expect("an address"),
            far
        ));
        for refused in [
            "0.0.0.0:5000",
            "203.0.113.9:0",
            "239.0.0.1:5000",
            "255.255.255.255:5000",
        ] {
            assert!(!warmable(v4(refused), far), "{refused} is nobody's mapping");
        }
        assert!(!warmable("[::]:5000".parse().expect("an address"), far));
        assert!(!warmable(
            "[ff02::1]:5000".parse().expect("an address"),
            far
        ));
        assert!(
            !warmable(v4("127.0.0.1:5000"), far),
            "a service on the network never observed a loopback source"
        );
        assert!(!warmable("[::1]:5000".parse().expect("an address"), far));
        assert!(
            warmable(v4("127.0.0.1:5000"), near),
            "a service on loopback observes nothing else"
        );
        assert!(warmable("[::1]:5000".parse().expect("an address"), near));
    }

    #[test]
    fn every_mapping_is_warmed_before_any_is_warmed_twice() {
        // A fetch's rails each punch for themselves, and a rail connects when
        // its own warming lands. Draining one mapping to exhaustion before
        // starting the next would leave the last rail connecting into a NAT
        // that was never opened for it.
        let service = v4("198.51.100.7:9000");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, &[service]);
        let key = key_of(&root);
        registrar.due(0);
        let rails: Vec<SocketAddr> = (0..4)
            .map(|index| v4(&format!("203.0.113.9:{}", 60_000 + index)))
            .collect();
        for rail in &rails {
            registrar.take(Datagram::Coming { key, fetch: *rail }, service);
        }
        let mut sent = Vec::new();
        for _ in 0..rails.len() * WARMING_DATAGRAMS {
            sent.extend(registrar.due(1).into_iter().map(|(to, _)| to));
        }
        assert_eq!(sent.len(), rails.len() * WARMING_DATAGRAMS);
        for round in sent.chunks(rails.len()) {
            let mut seen = round.to_vec();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), rails.len(), "a round warms each rail once");
        }
        assert_eq!(registrar.due(1), Vec::new(), "and no more than it owes");
    }

    #[test]
    fn a_cadence_of_warmings_is_bounded_however_many_fetches_come() {
        let service = v4("198.51.100.7:9000");
        let root = [9; 32];
        let mut registrar = Registrar::new(&root, &[service]);
        let key = key_of(&root);
        registrar.due(0);
        for index in 0..100_u16 {
            let fetch = SocketAddr::new(v4("203.0.113.9:0").ip(), 1_000 + index);
            registrar.take(Datagram::Coming { key, fetch }, service);
        }
        let mut warmings = 0;
        for _ in 0..WARMINGS_PER_CADENCE * 4 {
            warmings += registrar
                .due(1)
                .iter()
                .filter(|(_, datagram)| *datagram == Datagram::Warming)
                .count();
        }
        assert_eq!(warmings, WARMINGS_PER_CADENCE);

        registrar.take(
            Datagram::Coming {
                key,
                fetch: v4("203.0.113.9:6000"),
            },
            service,
        );
        assert_eq!(registrar.due(2), Vec::new(), "still inside the cadence");
        let opened = registrar.due(REGISTER_CADENCE_MS);
        assert_eq!(
            opened,
            vec![(service, Datagram::Register { key })],
            "the cadence turns over"
        );
        registrar.take(
            Datagram::Coming {
                key,
                fetch: v4("203.0.113.9:6000"),
            },
            service,
        );
        assert_eq!(
            registrar.due(REGISTER_CADENCE_MS),
            vec![(v4("203.0.113.9:6000"), Datagram::Warming)]
        );
    }

    #[test]
    fn a_key_holds_one_mapping_per_family_and_each_expires_alone() {
        // A serve reaches the service in each family it has, and each of
        // those arrives under an address only that family can use. A resolve
        // is answered in the family it came over, because that is the only
        // one the asker can reach a mapping in.
        let mut pairings = Pairings::default();
        let key = [5; 32];
        let over_v4 = v4("198.51.100.1:4433");
        let over_v6: SocketAddr = "[2001:db8::1]:4433".parse().expect("an address");
        let asking_v4 = v4("203.0.113.9:60123");
        let asking_v6: SocketAddr = "[2001:db8::9]:60123".parse().expect("an address");

        pairings.take(Datagram::Register { key }, over_v4, 0);
        assert_eq!(
            pairings.take(Datagram::Resolve { key }, asking_v6, 1).reply,
            Some(Datagram::Resolved { key, serve: None }),
            "an IPv4 mapping is no answer to an asker that has only IPv6"
        );
        assert_eq!(
            pairings.take(Datagram::Resolve { key }, asking_v4, 1).reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(over_v4)
            })
        );

        // The same serve registers over its other family, under one key.
        pairings.take(Datagram::Register { key }, over_v6, 2);
        let answered = pairings.take(Datagram::Resolve { key }, asking_v6, 3);
        assert_eq!(
            answered.reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(over_v6)
            })
        );
        assert_eq!(
            answered.notify,
            Some((
                over_v6,
                Datagram::Coming {
                    key,
                    fetch: asking_v6
                }
            )),
            "and the serve is told in the family the fetch can be reached in"
        );

        // One family ages out on its own clock and the other stands.
        let v4_gone = REGISTRATION_TTL_MS;
        assert_eq!(
            pairings
                .take(Datagram::Resolve { key }, asking_v4, v4_gone)
                .reply,
            Some(Datagram::Resolved { key, serve: None }),
            "the IPv4 registration is past its TTL"
        );
        assert_eq!(
            pairings
                .take(Datagram::Resolve { key }, asking_v6, v4_gone)
                .reply,
            Some(Datagram::Resolved {
                key,
                serve: Some(over_v6)
            }),
            "and the IPv6 one, registered later, is not"
        );
        assert_eq!(
            pairings.registered.len(),
            1,
            "one key, however many families it holds"
        );
    }

    #[test]
    fn a_fresh_register_below_the_cap_keeps_what_expired() {
        // The sweep waits for the cap: an expired key stays until a full
        // table forces the walk, so no datagram pays for the table's size.
        let mut pairings = Pairings::default();
        pairings.take(Datagram::Register { key: [1; 32] }, v4("192.0.2.1:1000"), 0);
        pairings.take(
            Datagram::Register { key: [2; 32] },
            v4("192.0.2.2:2000"),
            REGISTRATION_TTL_MS + 1,
        );
        assert_eq!(
            pairings.registered.len(),
            2,
            "an expired key is kept until the cap forces the sweep"
        );
    }

    #[test]
    fn the_table_is_bounded_and_full_is_shed_not_evicted() {
        let mut pairings = Pairings::default();
        // Filled directly: through take() a hostile mutant of the cap check
        // makes this fill quadratic, and the boundary below still crosses
        // the real path.
        for index in 0..MAX_REGISTRATIONS {
            let mut key = [0; 32];
            key[..8].copy_from_slice(&(index as u64).to_be_bytes());
            pairings.registered.insert(
                key,
                Mappings {
                    v4: Some(Registration {
                        mapping: v4("192.0.2.1:1000"),
                        expires_at_ms: REGISTRATION_TTL_MS,
                    }),
                    v6: None,
                },
            );
        }
        assert_eq!(pairings.registered.len(), MAX_REGISTRATIONS);
        let extra = pairings.take(
            Datagram::Register { key: [0xFF; 32] },
            v4("192.0.2.2:2000"),
            0,
        );
        assert_eq!(extra, Answer::default());
        assert_eq!(pairings.registered.len(), MAX_REGISTRATIONS);
        let mut held = [0; 32];
        held[..8].copy_from_slice(&0_u64.to_be_bytes());
        let refreshed = pairings.take(Datagram::Register { key: held }, v4("192.0.2.3:3000"), 1);
        assert_eq!(refreshed.reply, Some(Datagram::Registered { key: held }));

        // A full table sweeps what has expired rather than shedding forever,
        // at the instant those registrations expire and not a millisecond
        // later: everything here was registered at 0 except the refresh above.
        let at_expiry = REGISTRATION_TTL_MS;
        let room = pairings.take(
            Datagram::Register { key: [0xFF; 32] },
            v4("192.0.2.2:2000"),
            at_expiry,
        );
        assert_eq!(room.reply, Some(Datagram::Registered { key: [0xFF; 32] }));
        assert_eq!(
            pairings.registered.len(),
            2,
            "the refreshed registration and the one the sweep made room for"
        );
    }
}
