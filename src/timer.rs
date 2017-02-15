// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

pub use self::implementation::Timer;

#[cfg(not(feature = "use-mock-crust"))]
mod implementation {
    use action::Action;
    use itertools::Itertools;
    use maidsafe_utilities::thread::{self, Joiner};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};
    use types::RoutingActionSender;

    struct Detail {
        deadlines: BTreeMap<Instant, Vec<u64>>,
        cancelled: bool,
    }

    /// Simple timer.
    pub struct Timer {
        next_token: u64,
        detail_and_cond_var: Arc<(Mutex<Detail>, Condvar)>,
        _worker: Joiner,
    }

    impl Timer {
        /// Creates a new timer, passing a channel sender used to send `Timeout` events.
        pub fn new(sender: RoutingActionSender) -> Self {
            let detail = Detail {
                deadlines: BTreeMap::new(),
                cancelled: false,
            };
            let detail_and_cond_var = Arc::new((Mutex::new(detail), Condvar::new()));
            let detail_and_cond_var_clone = detail_and_cond_var.clone();
            let worker = thread::named("Timer", move || Self::run(sender, detail_and_cond_var));
            Timer {
                next_token: 0,
                detail_and_cond_var: detail_and_cond_var_clone,
                _worker: worker,
            }
        }

        /// Schedules a timeout event after `duration`. Returns a token that can be used to identify
        /// the timeout event.
        pub fn schedule(&mut self, duration: Duration) -> u64 {
            let token = self.next_token;
            self.next_token = token.wrapping_add(1);
            let &(ref mutex, ref cond_var) = &*self.detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            detail.deadlines.entry(Instant::now() + duration).or_insert_with(Vec::new).push(token);
            cond_var.notify_one();
            token
        }

        fn run(sender: RoutingActionSender, detail_and_cond_var: Arc<(Mutex<Detail>, Condvar)>) {
            let &(ref mutex, ref cond_var) = &*detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            while !detail.cancelled {
                // Handle expired deadlines.
                let now = Instant::now();
                let expired_list = detail.deadlines
                    .keys()
                    .take_while(|&&deadline| deadline < now)
                    .cloned()
                    .collect_vec();
                for expired in expired_list {
                    // Safe to call `expect()` as we just got the key we're removing from
                    // `deadlines`.
                    let tokens = detail.deadlines.remove(&expired).expect("Bug in `BTreeMap`.");
                    for token in tokens {
                        let _ = sender.send(Action::Timeout(token));
                    }
                }

                // If we have no deadlines pending, wait indefinitely.  Otherwise wait until the
                // nearest deadline.
                if detail.deadlines.is_empty() {
                    detail = cond_var.wait(detail).expect("Failed to lock.");
                } else {
                    // Safe to call `expect()` as `deadlines` has at least one entry.
                    let nearest =
                        detail.deadlines.keys().next().cloned().expect("Bug in `BTreeMap`.");
                    let duration = nearest - now;
                    detail = cond_var.wait_timeout(detail, duration).expect("Failed to lock.").0;
                }
            }
        }
    }

    impl Drop for Timer {
        fn drop(&mut self) {
            let &(ref mutex, ref cond_var) = &*self.detail_and_cond_var;
            let mut detail = mutex.lock().expect("Failed to lock.");
            detail.cancelled = true;
            cond_var.notify_one();
        }
    }

    #[cfg(test)]
    mod tests {
        use action::Action;
        use maidsafe_utilities::event_sender::MaidSafeEventCategory;
        use std::sync::mpsc;
        use std::thread;
        use std::time::{Duration, Instant};
        use super::*;
        use types::RoutingActionSender;

        #[test]
        fn schedule() {
            let (action_sender, action_receiver) = mpsc::channel();
            let (category_sender, category_receiver) = mpsc::channel();
            let routing_event_category = MaidSafeEventCategory::Routing;
            let sender = RoutingActionSender::new(action_sender,
                                                  routing_event_category,
                                                  category_sender.clone());
            let interval = Duration::from_millis(500);
            let instant_when_added;
            let check_no_events_received = || {
                let category = category_receiver.try_recv();
                assert!(category.is_err(),
                        "Expected no event, but received {:?}",
                        category);
                let action = action_receiver.try_recv();
                assert!(action.is_err(),
                        "Expected no event, but received {:?}",
                        action);
            };
            {
                let mut timer = Timer::new(sender);

                // Add deadlines, the first to time out after 2.5s, the second after 2.0s, and so on
                // down to 500ms.
                let count = 5;
                for i in 0..count {
                    let timeout = interval * (count - i);
                    let token = timer.schedule(timeout);
                    assert_eq!(token, i as u64);
                }

                // Ensure timeout notifications are received correctly.
                thread::sleep(Duration::from_millis(100));
                for i in 0..count {
                    check_no_events_received();
                    thread::sleep(interval);

                    let category = category_receiver.try_recv();
                    match category.expect("Should have received a category.") {
                        MaidSafeEventCategory::Routing => (),
                        unexpected_category => {
                            panic!("Expected `MaidSafeEventCategory::Routing`, but received {:?}",
                                   unexpected_category);
                        }
                    }
                    let action = action_receiver.try_recv();
                    match action.expect("Should have received an action.") {
                        Action::Timeout(token) => assert_eq!(token, (count - i - 1) as u64),
                        unexpected_action => {
                            panic!("Expected `Action::Timeout`, but received {:?}",
                                   unexpected_action);
                        }
                    }
                }

                // Add deadline and check that dropping `timer` doesn't fire a timeout notification,
                // and that dropping doesn't block until the deadline has expired.
                instant_when_added = Instant::now();
                let _ = timer.schedule(interval);
            }

            assert!(Instant::now() - instant_when_added < interval,
                    "`Timer::drop()` is blocking.");

            thread::sleep(interval + Duration::from_millis(100));
            check_no_events_received();
        }
    }
}

#[cfg(feature = "use-mock-crust")]
mod implementation {
    use std::time::Duration;
    use wheel_timer::WheelTimer;

    use types::RoutingActionSender;

    const TICKS_PER_SECOND: usize = 100;
    const WHEEL_INTERVAL: usize = 60 * 60 * TICKS_PER_SECOND;

    // The mock timer raises timeout events!
    pub struct Timer {
        next_token: u64,
        timer: WheelTimer<u64>,
    }

    // TODO: work out an alright conversion rule.
    fn duration_to_ticks(duration: Duration) -> usize {
        duration.as_secs() as usize * TICKS_PER_SECOND
    }

    impl Timer {
        pub fn new(_: RoutingActionSender) -> Self {
            Timer { next_token: 0, timer: WheelTimer::new(WHEEL_INTERVAL) }
        }

        pub fn schedule(&mut self, duration: Duration) -> u64 {
            let token = self.next_token;
            let wait_time = duration_to_ticks(duration);
            trace!("Scheduling a new timer to be available in {} ticks", wait_time);
            self.timer.schedule(wait_time, token);
            self.next_token = token.wrapping_add(1);
            token
        }

        /// Advance the timer forward one click, returning the tokens for any timeouts
        /// that expire as a result.
        pub fn tick(&mut self) -> Vec<u64> {
            self.timer.tick()
        }
    }
}
