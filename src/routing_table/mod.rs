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


// A routing table to manage contacts for a node in a [Kademlia][1] distributed hash table.
//
// [1]: https://en.wikipedia.org/wiki/Kademlia
//
//
// This uses the Kademlia mechanism for routing messages in a peer-to-peer network, and generalises
// it to provide redundancy in every step: for senders, messages in transit and receivers.
// It contains the routing table and the functionality to decide via which of its entries to route
// a message, but not the networking functionality itself.
//
// It also provides methods to decide which other nodes to connect to, depending on a parameter
// `bucket_size` (see below).
//
//
// # Addresses and distance functions
//
// Nodes in the network are addressed with a [`Xorable`][2] type, an unsigned integer with `B` bits.
// The *[XOR][3] distance* between two nodes with addresses `x` and `y` is `x ^ y`. This
// [distance function][4] has the property that no two points ever have the same distance from a
// given point, i. e. if `x ^ y == x ^ z`, then `y == z`. This property allows us to define the
// `k`-*close group* of an address as the `k` closest nodes to that address, guaranteeing that the
// close group will always have exactly `k` members (unless, of course, the whole network has less
// than `k` nodes).
//
// [2]: trait.Xorable.html
// [3]: https://en.wikipedia.org/wiki/Exclusive_or#Bitwise_operation
// [4]: https://en.wikipedia.org/wiki/Metric_%28mathematics%29
//
// The routing table is associated with a node with some name `x`, and manages a number of contacts
// to other nodes, sorting them into up to `B` *buckets*, depending on their XOR distance from `x`:
//
// * If 2<sup>`B`</sup> > `x ^ y` >= 2<sup>`B - 1`</sup>, then y is in bucket 0.
// * If 2<sup>`B - 1`</sup> > `x ^ y` >= 2<sup>`B - 2`</sup>, then y is in bucket 1.
// * If 2<sup>`B - 2`</sup> > `x ^ y` >= 2<sup>`B - 3`</sup>, then y is in bucket 2.
// * ...
// * If 2 > `x ^ y` >= 1, then y is in bucket `B - 1`.
//
// Equivalently, `y` is in bucket `n` if the longest common prefix of `x` and `y` has length `n`,
// i. e. the first binary digit in which `x` and `y` disagree is the `(n + 1)`-th one. We call the
// length of the remainder, without the common prefix, the *bucket distance* of `x` and `y`. Hence
// `x` and `y` have bucket distance `B - n` if and only if `y` belongs in bucket number `n`.
//
// The bucket distance is coarser than the XOR distance: Whenever the bucket distance from `y` to
// `x` is less than the bucket distance from `z` to `x`, then `y ^ x < z ^ x`. But not vice-versa:
// Often `y ^ x < z ^ x`, even if the bucket distances are equal. The XOR distance ranges from 0
// to 2<sup>`B`</sup> (exclusive), while the bucket distance ranges from 0 to `B` (inclusive).
//
//
// # Guarantees
//
// The routing table provides functions to decide, for a message with a given destination, which
// nodes in the table to pass the message on to, so that it is guaranteed that:
//
// * If the destination is the address of a node, the message will reach that node after at most
//   `B - 1` hops.
// * Otherwise, if the destination is a `k`-close group with `k <= min_section_size`, the message
//   will reach every member of the `k`-close group of the destination address, i.e. all `k` nodes
//   in the network that are XOR-closest to that address, and each node knows whether it belongs to
//   that group.
// * Each node in a given address' close group is connected to each other node in that section. In
//   particular, every node is connected to its own close group.
// * The number of total hop messages created for each message is at most `B`.
// * There are `min_section_size` different paths along which a message can be sent, to provide
//   redundancy.
//
// However, to be able to make these guarantees, the routing table must be filled with sufficiently
// many contacts. Specifically, the following invariant must be ensured:
//
// > Whenever a bucket `n` has fewer than `bucket_size` entries, it contains *all* nodes in the
// > network with bucket distance `B - n`.
//
// The user of this crate therefore needs to make sure that whenever a node joins or leaves, all
// affected nodes in the network update their routing tables accordingly.
//
//
// # Resilience against malfunctioning nodes
//
// The sender may choose to send a message via up to `bucket_size` distinct paths to provide
// redundancy against malfunctioning hop nodes. These paths are likely, but not guaranteed, to be
// disjoint.
//
// The concept of sections exists to provide resilience even against failures of the source or
// destination itself: If every member of a section tries to send the same message, it will arrive
// even if some members fail. And if a message is sent to a whole section, it will arrive in most,
// even if some of them malfunction.
//
// Close sections can thus be used as inherently redundant authorities in the network that messages
// can be sent to and received from, using a consensus algorithm: A message from a section authority
// is considered to be legitimate, if a majority of section members have sent a message with the
// same content.

mod authority;
mod error;
mod network_tests;
mod prefix;
mod xorable;

use itertools::Itertools;
pub use self::authority::Authority;
pub use self::error::Error;
#[cfg(any(test, feature = "use-mock-crust"))]
pub use self::network_tests::verify_network_invariant;
pub use self::prefix::Prefix;
pub use self::xorable::Xorable;
use std::{iter, mem};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet, btree_map, hash_set};
use std::collections::btree_map::Entry;
use std::fmt::{Binary, Debug, Formatter};
use std::fmt::Result as FmtResult;
use std::hash::Hash;

pub type Sections<T> = BTreeMap<Prefix<T>, HashSet<T>>;

type MemberIter<'a, T> = hash_set::Iter<'a, T>;
type SectionIter<'a, T> = btree_map::Values<'a, Prefix<T>, HashSet<T>>;
type OtherSectionsIter<'a, T> = iter::FlatMap<SectionIter<'a, T>,
                                              MemberIter<'a, T>,
                                              FlatMapFn<'a, T>>;
type FlatMapFn<'a, T> = fn(&'a HashSet<T>) -> MemberIter<'a, T>;

// Amount added to `min_section_size` when deciding whether a bucket split can happen.  This helps
// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 1;

// Immutable iterator over the entries of a `RoutingTable`.
pub struct Iter<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> {
    inner: iter::Chain<OtherSectionsIter<'a, T>, hash_set::Iter<'a, T>>,
    our_name: T,
}

impl<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> Iterator for Iter<'a, T> {
    type Item = &'a T;

    #[cfg_attr(feature="cargo-clippy", allow(while_let_on_iterator))]
    fn next(&mut self) -> Option<&'a T> {
        while let Some(name) = self.inner.next() {
            if *name != self.our_name {
                return Some(name);
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}


// Used when removal of a contact triggers the need to merge two or more sections.  Sent between all
// members of all merging sections, but not peers outwith the new section. Contains all sections in
// the routing table of nodes with the sender prefix.
#[derive(Clone, Debug, PartialEq)]
pub struct OwnMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    pub sender_prefix: Prefix<T>,
    pub merge_prefix: Prefix<T>,
    pub sections: Sections<T>,
}



// Used once merging our own section has completed to send to peers outwith the new section
#[derive(Clone, Debug, PartialEq)]
pub struct OtherMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    pub prefix: Prefix<T>,
    pub section: HashSet<T>,
}



// Details returned by a successful `RoutingTable::remove()`.
#[derive(Debug)]
pub struct RemovalDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    // Peer name
    pub name: T,
    // True if the removed peer was in our section.
    pub was_in_our_section: bool,
}



// Details returned by `RoutingTable::merge_own_section()`.
pub enum OwnMergeState<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    // If an ongoing merge is happening, and this call to `merge_own_section()` doesn't complete the
    // merge (i.e. at least one of the merging sections hasn't yet sent us its merge details), then
    // `Ongoing` is returned, implying that no further action by the caller is required.
    Ongoing,
    // If an ongoing merge is happening, and this call to `merge_own_section()` completes the merge
    // (i.e. all merging sections have sent us their merge details), then `Completed` is returned,
    // containing the appropriate targets (the `Prefix`es of all sections outwith the merging ones)
    // and the merge details they each need to receive (the new prefix and merged section).
    Completed {
        targets: BTreeSet<Prefix<T>>,
        merge_details: OtherMergeDetails<T>,
    },
    // The merge has already completed, implying that no further action by the caller is required.
    AlreadyMerged,
}



/// A routing table to manage contacts for a node.
///
/// It maintains a list of sections (identified by a `Prefix<T>`), each with a
/// list node identifiers of type `T` (e.g. `XorName`) representing connected
/// peer nodes, and provides algorithms for routing messages.
///
/// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> {
    // Minimum number of nodes we consider acceptable in a section
    min_section_size: usize,
    // Name of node holding this table
    our_name: T,
    // Prefix of our section
    our_prefix: Prefix<T>,
    // Members of our section, including our own name
    our_section: HashSet<T>,
    // Other sections (excludes our own) (TODO: rename)
    sections: Sections<T>,
    // Whether we have sent our merge details to the other section.
    we_want_to_merge: bool,
    // Whether the other section has sent their merge details to us.
    they_want_to_merge: bool,
}

impl<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> RoutingTable<T> {
    /// Creates a new `RoutingTable`.
    pub fn new(our_name: T, min_section_size: usize) -> Self {
        let mut our_section = HashSet::new();
        our_section.insert(our_name);
        RoutingTable {
            our_name: our_name,
            min_section_size: min_section_size,
            our_section: our_section,
            our_prefix: Default::default(),
            sections: BTreeMap::new(),
            we_want_to_merge: false,
            they_want_to_merge: false,
        }
    }

    /// Adds the list of `Prefix`es as empty sections.
    ///
    /// Called once a node has been approved by its own section and is given its peers' tables.
    /// Expects the current sections to be empty.
    pub fn add_prefixes(&mut self, prefixes: Vec<Prefix<T>>) -> Result<(), Error> {
        if !self.sections.is_empty() {
            return Err(Error::InvariantViolation);
        }
        for prefix in prefixes {
            if prefix.matches(&self.our_name) {
                self.our_prefix = prefix;
            } else if self.sections.insert(prefix, HashSet::new()).is_some() {
                return Err(Error::InvariantViolation);
            };
        }
        // In case our section has split while we've been going through the approval process, we
        // need to assign the original members of our section to the new appropriate sections.
        let our_section = mem::replace(&mut self.our_section, HashSet::new());
        for name in our_section {
            if self.get_section_mut(&name).map_or(true, |section| !section.insert(name)) {
                return Err(Error::InvariantViolation);
            }
        }
        self.check_invariant(true, true)
    }

    /// Returns the `Prefix` of our section
    pub fn our_prefix(&self) -> &Prefix<T> {
        &self.our_prefix
    }

    /// Returns our own section, including our own name.
    pub fn our_section(&self) -> &HashSet<T> {
        &self.our_section
    }

    /// Returns the whole routing table, including our section and our name
    pub fn all_sections(&self) -> Sections<T> {
        self.sections
            .clone()
            .into_iter()
            .chain(iter::once((self.our_prefix, self.our_section.clone())))
            .collect()
    }

    /// Returns the section with the given prefix, if any (includes own name if is own section)
    pub fn section_with_prefix(&self, prefix: &Prefix<T>) -> Option<&HashSet<T>> {
        if *prefix == self.our_prefix {
            Some(&self.our_section)
        } else {
            self.sections.get(prefix)
        }
    }

    /// Returns the total number of entries in the routing table, excluding our own name.
    // TODO: refactor to include our name?
    pub fn len(&self) -> usize {
        self.sections.values().fold(0, |acc, section| acc + section.len()) +
        self.our_section.len() - 1
    }

    /// Is the table empty? (Returns `true` if no nodes besides our own are known;
    /// empty sections are ignored.)
    pub fn is_empty(&self) -> bool {
        self.our_section.len() == 1 && self.sections.values().all(HashSet::is_empty)
    }

    /// Returns the minimum section size.
    pub fn min_section_size(&self) -> usize {
        self.min_section_size
    }

    /// Returns the number of nodes which need to exist in each subsection of a given section to
    /// allow it to be split.
    pub fn min_split_size(&self) -> usize {
        self.min_section_size + SPLIT_BUFFER
    }

    /// Returns whether the table contains the given `name`.
    pub fn has(&self, name: &T) -> bool {
        self.get_section(name).map_or(false, |section| section.contains(name))
    }

    /// Iterates over all nodes known by the routing table, excluding our own name.
    // TODO: do we need to exclude our name?
    pub fn iter(&self) -> Iter<T> {
        let iter: fn(_) -> _ = HashSet::iter;
        Iter {
            inner: self.sections.values().flat_map(iter).chain(self.our_section.iter()),
            our_name: self.our_name,
        }
    }

    /// Tests whether the given prefix is in our routing table
    pub fn has_prefix(&self, prefix: &Prefix<T>) -> bool {
        self.our_prefix == *prefix || self.sections.keys().any(|k| k == prefix)
    }

    /// Compute an estimate of the size of the network from the size of our routing table.
    ///
    /// Return (estimate, exact), with exact = true iff we have the whole network in our
    /// routing table.
    pub fn network_size_estimate(&self) -> (u64, bool) {
        let known_prefixes = self.prefixes();
        let is_exact = Prefix::default().is_covered_by(known_prefixes.iter());

        // Estimated fraction of the network that we have in our RT.
        // Computed as the sum of 1 / 2^(prefix.bit_count) for all known section prefixes.
        let network_fraction: f64 = known_prefixes.iter()
            .map(|p| 1.0 / (p.bit_count() as f64).exp2())
            .sum();

        // Total size estimate = known_nodes / network_fraction
        let network_size = (self.len() + 1) as f64 / network_fraction;

        (network_size.ceil() as u64, is_exact)
    }

    /// Collects prefixes of all sections known by the routing table other than ours into a
    /// `BTreeSet`.
    pub fn other_prefixes(&self) -> BTreeSet<Prefix<T>> {
        self.sections.keys().cloned().collect()
    }

    /// Collects prefixes of all sections known by the routing table into a `BTreeSet`.
    pub fn prefixes(&self) -> BTreeSet<Prefix<T>> {
        self.sections.keys().cloned().chain(iter::once(self.our_prefix)).collect()
    }

    /// If our section is the closest one to `name`, returns all names in our section *including
    /// ours*, otherwise returns `None`.
    pub fn close_names(&self, name: &T) -> Option<HashSet<T>> {
        if self.our_prefix.matches(name) {
            Some(self.our_section().clone())
        } else {
            None
        }
    }

    /// If our section is the closest one to `name`, returns all names in our section *excluding
    /// ours*, otherwise returns `None`.
    pub fn other_close_names(&self, name: &T) -> Option<HashSet<T>> {
        if self.our_prefix.matches(name) {
            let mut section = self.our_section.clone();
            section.remove(&self.our_name);
            Some(section)
        } else {
            None
        }
    }

    /// Are we among the `count` closest nodes to `name`?
    pub fn is_closest(&self, name: &T, count: usize) -> bool {
        self.closest_names(name, count).is_some()
    }

    // Finds the `count` names closest to `name` in the whole routing table
    fn closest_known_names(&self, name: &T, count: usize) -> Vec<&T> {
        self.sections
            .iter()
            .chain(iter::once((&self.our_prefix, &self.our_section)))
            .sorted_by(|&(pfx0, _), &(pfx1, _)| pfx0.cmp_distance(pfx1, name))
            .into_iter()
            .flat_map(|(_, section)| {
                section.iter().sorted_by(|name0, name1| name.cmp_distance(name0, name1))
            })
            .take(count)
            .collect_vec()
    }

    /// Returns the `count` closest entries to `name` in the routing table, including our own name,
    /// sorted by ascending distance to `name`. If we are not close, returns `None`.
    pub fn closest_names(&self, name: &T, count: usize) -> Option<Vec<&T>> {
        let result = self.closest_known_names(name, count);
        if result.contains(&&self.our_name) {
            Some(result)
        } else {
            None
        }
    }

    /// Returns the `count-1` closest entries to `name` in the routing table, excluding
    /// our own name, sorted by ascending distance to `name` -  or `None`, if our name
    /// isn't among `count` names closest to `name`.
    pub fn other_closest_names(&self, name: &T, count: usize) -> Option<Vec<&T>> {
        self.closest_names(name, count).map(|mut result| {
            result.retain(|name| *name != &self.our_name);
            result
        })
    }

    /// Returns true if `name` is in our section (including if it is our own name).
    pub fn is_in_our_section(&self, name: &T) -> bool {
        self.our_section.contains(name)
    }

    /// Returns `Ok(())` if the given contact should be added to the routing table.
    ///
    /// Returns `Err` if `name` already exists in the routing table, or it doesn't fall within any
    /// of our sections, or it's our own name.
    pub fn need_to_add(&self, name: &T) -> Result<(), Error> {
        if *name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }
        if let Some(section) = self.get_section(name) {
            if section.contains(name) {
                Err(Error::AlreadyExists)
            } else {
                Ok(())
            }
        } else {
            Err(Error::PeerNameUnsuitable)
        }
    }

    /// Returns `Err(Error::PeerNameUnsuitable)` if `name` is not within our section, or
    /// `Err(Error::AlreadyExists)` if `name` is already in our table.
    pub fn should_join_our_section(&self, name: &T) -> Result<(), Error> {
        if !self.our_prefix.matches(name) {
            return Err(Error::PeerNameUnsuitable);
        }
        if self.our_section.contains(name) {
            return Err(Error::AlreadyExists);
        }
        Ok(())
    }

    /// Validates a joining node's name.
    pub fn validate_joining_node(&self, name: &T) -> Result<(), Error> {
        if !self.our_prefix.matches(name) {
            return Err(Error::PeerNameUnsuitable);
        }
        if self.our_section.contains(name) {
            return Err(Error::AlreadyExists);
        }
        Ok(())
    }

    /// Adds a contact to the routing table.
    ///
    /// Returns `Err` if `name` already existed in the routing table, or it doesn't fall within any
    /// of our sections, or it's our own name.  Otherwise it returns `Ok(true)` if the addition
    /// succeeded and should cause our section to split or `Ok(false)` if the addition succeeded and
    /// shouldn't cause a split.
    pub fn add(&mut self, name: T) -> Result<(), Error> {
        if name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }

        if let Some(section) = self.get_section_mut(&name) {
            if !section.insert(name) {
                return Err(Error::AlreadyExists);
            }
        } else {
            return Err(Error::PeerNameUnsuitable);
        }

        Ok(())
    }

    /// Returns true if our section should split.
    pub fn we_should_split(&self) -> bool {
        let split_size = self.min_split_size();
        let close_to_merging_with_us = |(prefix, section): (&Prefix<T>, &HashSet<T>)| {
            prefix.popped().is_compatible(&self.our_prefix) && section.len() < split_size
        };
        // If we're currently merging or are close to merging, we shouldn't split.
        if self.we_want_to_merge || self.they_want_to_merge ||
           self.sections.iter().any(close_to_merging_with_us) {
            return false;
        }

        // Count the number of names which will end up in each new section if our section is split.
        let new_size = self.our_section
            .iter()
            .filter(|name| self.our_name.common_prefix(name) > self.our_prefix.bit_count())
            .count();
        // If either of the two new sections will not contain enough entries, return `false`.
        new_size >= split_size && self.our_section().len() >= split_size + new_size
    }

    /// Splits a section.
    ///
    /// If the section exists in the routing table, it is split, otherwise this function is a no-op.
    /// If any of the sections don't satisfy the invariant any more (i.e. only differ in one bit
    /// from our own prefix), they are removed and those contacts are returned.  If the split is
    /// happening to our own section, our new prefix is returned in the optional field.
    pub fn split(&mut self, prefix: Prefix<T>) -> (Vec<T>, Option<Prefix<T>>) {
        let mut result = vec![];
        if prefix == self.our_prefix {
            result = self.split_our_section();
            return (result, Some(self.our_prefix));
        }

        if let Some(to_split) = self.sections.remove(&prefix) {
            let prefix0 = prefix.pushed(false);
            let prefix1 = prefix.pushed(true);
            let (section0, section1) = to_split.into_iter()
                .partition::<HashSet<_>, _>(|name| prefix0.matches(name));

            for (pfx, section) in vec![(prefix0, section0), (prefix1, section1)] {
                if self.our_prefix.is_neighbour(&pfx) {
                    self.insert_new_section(pfx, section);
                } else {
                    result.extend(section);
                }
            }
        }
        (result, None)
    }

    /// Adds the given prefix to the routing table, merging or splitting if necessary. Returns the
    /// entries that have been dropped.
    pub fn add_prefix(&mut self, prefix: Prefix<T>) -> Vec<T> {
        let mut result = vec![];
        if self.our_prefix == prefix || self.sections.contains_key(&prefix) {
            return result; // We already have this section: Nothing to do!
        }
        // While `prefix` extends an existing entry, split that entry.
        while let Some(&shorter_pfx) =
            self.sections
                .keys()
                .chain(iter::once(&self.our_prefix))
                .find(|p| p.is_compatible(&prefix) && p.bit_count() < prefix.bit_count()) {
            let (dropped_nodes, _opt_our_pfx) = self.split(shorter_pfx);
            result.extend(dropped_nodes);
        }

        // If it's neither our neighbour nor compatible, we need to merge our own until it is
        // compatible.
        let mut our_prefix = self.our_prefix;
        while !our_prefix.is_neighbour(&prefix) && !our_prefix.is_compatible(&prefix) {
            our_prefix = our_prefix.popped();
        }
        self.merge(&our_prefix);

        // Merge if necessary, then add empty sections to satisfy the requirement that for each `i`,
        // the own prefix with the `i`-th bit flipped must be covered. To do this, split each such
        // prefix recursively until all its parts are either covered or incompatible with the
        // existing ones. Insert the incompatible ones to cover the required part of the name space.
        self.merge(&prefix);
        self.add_missing_prefixes();
        result
    }

    /// Removes a contact from the routing table.
    ///
    /// If no entry with that name is found, `Err(Error::NoSuchPeer)` is returned.  Otherwise, the
    /// entry is removed from the routing table and `RemovalDetails` is returned.  See that struct's
    /// docs for further info.
    pub fn remove(&mut self, name: &T) -> Result<RemovalDetails<T>, Error> {
        let removal_details = RemovalDetails {
            name: *name,
            was_in_our_section: self.our_prefix.matches(name),
        };
        if removal_details.was_in_our_section {
            if self.our_name == *name {
                return Err(Error::OwnNameDisallowed);
            }
            if !self.our_section.remove(name) {
                return Err(Error::NoSuchPeer);
            }
        } else if let Some(prefix) = self.find_section_prefix(name) {
            if let Some(section) = self.sections.get_mut(&prefix) {
                if !section.remove(name) {
                    return Err(Error::NoSuchPeer);
                }
            }
        } else {
            return Err(Error::NoSuchPeer);
        }
        Ok(removal_details)
    }

    /// Returns whether the other section has already initiated a merge.
    pub fn they_want_to_merge(&self) -> bool {
        self.they_want_to_merge
    }

    /// If our section is required to merge, returns the details to initiate merging.
    ///
    /// Merging is required if any section has dropped below the minimum size and can only restore
    /// it by ultimately merging with us.
    ///
    /// However, merging happens in simple steps, each of which involves only two sections. If. e.g.
    /// section `1` drops below the minimum size, and the other sections are `01`, `001` and `000`,
    /// then this will return `true` only in the latter two. Once they are merged and have
    /// established all their new connections, it will return `true` in `01` and `00`. Only after
    /// that, the section `0` will merge with section `1`.
    pub fn should_merge(&self) -> Option<OwnMergeDetails<T>> {
        let bit_count = self.our_prefix.bit_count();
        let doesnt_need_to_merge_with_us = |(prefix, section): (&Prefix<T>, &HashSet<T>)| {
            !prefix.popped().is_compatible(&self.our_prefix) ||
            section.len() >= self.min_section_size
        };
        if bit_count == 0 || self.we_want_to_merge ||
           !self.sections.contains_key(&self.our_prefix.with_flipped_bit(bit_count - 1)) {
            return None; // We can't merge, or we already sent our merge message.
        }
        if !self.they_want_to_merge && self.our_section.len() >= self.min_section_size &&
           self.sections.iter().all(doesnt_need_to_merge_with_us) {
            return None; // There is no reason to merge.
        }
        let merge_prefix = self.our_prefix.popped();
        Some(OwnMergeDetails {
            sender_prefix: self.our_prefix,
            merge_prefix: merge_prefix,
            sections: self.all_sections(),
        })
    }

    /// When a merge of our own section is triggered (either from our own section or a neighbouring
    /// one) this function handles the incoming merge details from the peers within the merging
    /// sections.
    ///
    /// The actual merge of the section is only done once all expected merging sections have
    /// provided details.  See the docs for `OwnMergeState` for full details of the return value.
    pub fn merge_own_section(&mut self, merge_details: OwnMergeDetails<T>) -> OwnMergeState<T> {
        // TODO: Return an error if they are not compatible instead?
        if !self.our_prefix.is_compatible(&merge_details.merge_prefix) ||
           self.our_prefix.bit_count() != merge_details.merge_prefix.bit_count() + 1 {
            debug!("{:?}: Attempt to call merge_own_section() for an already merged prefix {:?}",
                   self.our_name,
                   merge_details.merge_prefix);
            return OwnMergeState::AlreadyMerged;
        }
        for prefix in merge_details.sections.keys() {
            if *prefix == self.our_prefix || self.sections.contains_key(prefix) {
                continue; // Already in our routing table.
            } else if self.our_prefix.is_compatible(prefix) ||
                      self.sections.keys().any(|pfx| prefix.is_compatible(pfx)) {
                error!("{:?} Received unsuitable prefix {:?} in OwnSectionMerge.",
                       self.our_name,
                       prefix);
            } else {
                self.insert_new_section(*prefix, HashSet::new());
            }
        }

        if merge_details.sender_prefix == self.our_prefix {
            self.we_want_to_merge = true;
        } else {
            self.they_want_to_merge = true;
        }
        if self.we_want_to_merge && self.they_want_to_merge {
            // We've heard from all merging sections - do the merge and return `Completed`.
            self.finish_merging_own_section(merge_details.merge_prefix)
        } else {
            // We don't have the merge details from both sides yet.
            OwnMergeState::Ongoing
        }
    }

    /// Merges all existing compatible sections into the new one defined by `merge_details.prefix`.
    /// Our own section is not included in the merge.
    ///
    /// The appropriate targets (all contacts from `merge_details.sections` which are not currently
    /// held in the routing table) are returned so the caller can establish connections to these
    /// peers and subsequently add them.
    pub fn merge_other_section(&mut self, merge_details: OtherMergeDetails<T>) -> HashSet<T> {
        if self.our_prefix.is_compatible(&merge_details.prefix) {
            // We've already handled this particular merge via `merge_own_section()`.
            return HashSet::new();
        }

        self.merge(&merge_details.prefix);

        // Establish list of provided contacts which are currently missing from our table.
        merge_details.section
            .difference(unwrap!(self.sections.get(&merge_details.prefix)))
            .cloned()
            .collect::<HashSet<_>>()
    }

    /// Returns a collection of nodes to which a message for the given `Authority` should be sent
    /// onwards.  In all non-error cases below, the returned collection will have the members of
    /// `exclude` removed, possibly resulting in an empty set being returned.
    ///
    /// * If the destination is an `Authority::Section`:
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `route`-th closest member of the RT to the target
    ///
    /// * If the destination is an `Authority::PrefixSection`:
    ///     - if the prefix is compatible with our prefix and is fully-covered by prefixes in our
    ///       RT, returns all members in these prefixes except ourself; otherwise
    ///     - if the prefix is compatible with our prefix and is *not* fully-covered by prefixes in
    ///       our RT, returns `Err(Error::CannotRoute)`; otherwise
    ///     - returns the `route`-th closest member of the RT to the lower bound of the target
    ///       prefix
    ///
    /// * If the destination is a group (`ClientManager`, `NaeManager` or `NodeManager`):
    ///     - if our section is the closest on the network (i.e. our section's prefix is a prefix of
    ///       the destination), returns all other members of our section; otherwise
    ///     - returns the `route`-th closest member of the RT to the target
    ///
    /// * If the destination is an individual node (`ManagedNode` or `Client`):
    ///     - if our name *is* the destination, returns an empty set; otherwise
    ///     - if the destination name is an entry in the routing table, returns it; otherwise
    ///     - returns the `route`-th closest member of the RT to the target
    pub fn targets(&self,
                   dst: &Authority<T>,
                   exclude: T,
                   route: usize)
                   -> Result<HashSet<T>, Error> {
        let candidates = |target_name: &T| {
            self.closest_known_names(target_name, self.min_section_size)
                .into_iter()
                .filter(|name| **name != self.our_name)
                .cloned()
                .collect::<HashSet<T>>()
        };

        let closest_section = match *dst {
            Authority::ManagedNode(ref target_name) |
            Authority::Client { proxy_node_name: ref target_name, .. } => {
                if *target_name == self.our_name {
                    return Ok(HashSet::new());
                }
                if self.has(target_name) {
                    return Ok(iter::once(*target_name).collect());
                }
                candidates(target_name)
            }
            Authority::ClientManager(ref target_name) |
            Authority::NaeManager(ref target_name) |
            Authority::NodeManager(ref target_name) => {
                if let Some(group) = self.other_closest_names(target_name, self.min_section_size) {
                    return Ok(group.into_iter().cloned().collect());
                }
                candidates(target_name)
            }
            Authority::Section(ref target_name) => {
                let (prefix, section) = self.closest_section(target_name);
                if *prefix == self.our_prefix {
                    // Exclude our name since we don't need to send to ourself
                    let mut section = section.clone();
                    section.remove(&self.our_name);
                    return Ok(section);
                }
                candidates(target_name)
            }
            Authority::PrefixSection(ref prefix) => {
                if prefix.is_compatible(&self.our_prefix) {
                    // only route the message when we have all the targets in our routing table -
                    // this is to prevent spamming the network by sending messages with
                    // intentionally short prefixes
                    if prefix.is_covered_by(self.prefixes().iter()) {
                        return Ok(self.iter()
                            .filter(|name| prefix.matches(name) && **name != self.our_name)
                            .cloned()
                            .collect());
                    } else {
                        return Err(Error::CannotRoute);
                    }
                }
                candidates(&prefix.lower_bound())
            }
        };
        Ok(iter::once(self.get_routeth_node(&closest_section, dst.name(), Some(exclude), route)?)
            .collect())
    }

    /// Returns whether we are a part of the given authority.
    pub fn in_authority(&self, auth: &Authority<T>) -> bool {
        match *auth {
            // clients have no routing tables
            Authority::Client { .. } => false,
            Authority::ManagedNode(ref name) => self.our_name == *name,
            Authority::ClientManager(ref name) |
            Authority::NaeManager(ref name) |
            Authority::NodeManager(ref name) => self.is_closest(name, self.min_section_size),
            Authority::Section(ref name) => self.our_prefix.matches(name),
            Authority::PrefixSection(ref prefix) => prefix.matches(&self.our_name),
        }
    }

    /// Returns the section matching the given `name`, if present.
    /// Includes our own name in the case that our prefix matches `name`.
    pub fn get_section(&self, name: &T) -> Option<&HashSet<T>> {
        if self.our_prefix.matches(name) {
            return Some(&self.our_section);
        }
        if let Some(prefix) = self.find_section_prefix(name) {
            return self.sections.get(&prefix);
        }
        None
    }

    /// Returns our name.
    pub fn our_name(&self) -> &T {
        &self.our_name
    }

    /// Returns whether the Routing invariant is currently held for this table or not.
    pub fn is_valid(&self) -> bool {
        self.check_invariant(false, false).is_ok()
    }

    /// Returns the prefix of the section in which `name` belongs, or `None` if there is no such
    /// section in the routing table.
    pub fn find_section_prefix(&self, name: &T) -> Option<Prefix<T>> {
        if self.our_prefix.matches(name) {
            return Some(self.our_prefix);
        }
        self.sections.keys().find(|&prefix| prefix.matches(name)).cloned()
    }

    /// Returns `name` modified so that it belongs to one of the known prefixes with minimal bit
    /// length, favouring our own prefix if it is one of the shortest.
    pub fn assign_to_min_len_prefix(&self, name: &T) -> T {
        let target_prefix = iter::once(&self.our_prefix)
            .chain(self.sections.keys())
            .min_by_key(|prefix| prefix.bit_count())
            .unwrap_or(&self.our_prefix);
        target_prefix.substituted_in(*name)
    }

    fn split_our_section(&mut self) -> Vec<T> {
        let next_bit = self.our_name.bit(self.our_prefix.bit_count());
        let other_prefix = self.our_prefix.pushed(!next_bit);
        self.our_prefix = self.our_prefix.pushed(next_bit);
        let (our_new_section, other_section) = self.our_section
            .iter()
            .partition::<HashSet<_>, _>(|name| self.our_prefix.matches(name));
        self.our_section = our_new_section;
        // Drop sections that ceased to be our neighbours.
        let sections_to_remove = self.sections
            .keys()
            .filter(|prefix| !prefix.is_neighbour(&self.our_prefix))
            .cloned()
            .collect_vec();
        self.insert_new_section(other_prefix, other_section);
        sections_to_remove.into_iter()
            .filter_map(|prefix| self.sections.remove(&prefix))
            .flat_map(HashSet::into_iter)
            .collect()
    }

    /// Inserts the given section. Logs an error if it already exists.
    fn insert_new_section(&mut self, prefix: Prefix<T>, section: HashSet<T>) {
        match self.sections.entry(prefix) {
            Entry::Vacant(entry) => {
                let _section_ref = entry.insert(section);
            }
            Entry::Occupied(entry) => {
                error!("{:?} Inserting section {:?}, but already has members {:?}. This is a bug!",
                       self.our_name,
                       prefix,
                       entry.get());
                entry.into_mut().extend(section);
            }
        }
    }

    fn finish_merging_own_section(&mut self, merge_prefix: Prefix<T>) -> OwnMergeState<T> {
        self.we_want_to_merge = false;
        self.they_want_to_merge = false;
        self.merge(&merge_prefix);
        self.add_missing_prefixes();
        let targets = self.sections.keys().cloned().collect();
        let other_details = OtherMergeDetails {
            prefix: merge_prefix,
            section: self.our_section().clone(),
        };
        OwnMergeState::Completed {
            targets: targets,
            merge_details: other_details,
        }
    }

    fn merge(&mut self, new_prefix: &Prefix<T>) {
        // Partition the sections into those for merging and the rest
        let original_sections = mem::replace(&mut self.sections, Sections::new());
        let (sections_to_merge, sections) = original_sections.into_iter()
            .partition::<BTreeMap<_, _>, _>(|&(prefix, _)| new_prefix.is_compatible(&prefix));
        self.sections = sections;
        // Merge selected sections and add the merged section back in.
        let merged_names = sections_to_merge.into_iter().flat_map(|(_, names)| names).collect();
        if self.our_prefix.is_compatible(new_prefix) {
            self.our_section.extend(merged_names);
            self.our_prefix = *new_prefix;
        } else {
            self.insert_new_section(*new_prefix, merged_names);
        }
    }

    /// Inserts empty sections so that the prefixes cover all neighbouring areas of the namespace.
    fn add_missing_prefixes(&mut self) {
        let mut missing_pfxs = (0..self.our_prefix.bit_count())
            .map(|i| self.our_prefix.with_flipped_bit(i))
            .collect_vec();
        while let Some(pfx) = missing_pfxs.pop() {
            if !pfx.is_covered_by(self.sections.keys()) {
                if self.sections.keys().any(|p| pfx.is_compatible(p)) {
                    missing_pfxs.push(pfx.pushed(true));
                    missing_pfxs.push(pfx.pushed(false));
                } else {
                    self.insert_new_section(pfx, HashSet::new());
                }
            }
        }
    }

    /// Get a mutable reference to whichever section matches the given name. If our own section,
    /// our name is included.
    fn get_section_mut(&mut self, name: &T) -> Option<&mut HashSet<T>> {
        if self.our_prefix.matches(name) {
            return Some(&mut self.our_section);
        }
        if let Some(prefix) = self.find_section_prefix(name) {
            return self.sections.get_mut(&prefix);
        }
        None
    }

    /// Returns the prefix of the closest non-empty section to `name`, regardless of whether `name`
    /// belongs in that section or not, and the section itself.
    fn closest_section(&self, name: &T) -> (&Prefix<T>, &HashSet<T>) {
        let mut result = (&self.our_prefix, &self.our_section);
        for (prefix, section) in &self.sections {
            if !section.is_empty() && result.0.cmp_distance(prefix, name) == Ordering::Greater {
                result = (prefix, section)
            }
        }
        result
    }

    /// Gets the `route`-th name from a collection of names
    fn get_routeth_name<'a, U: IntoIterator<Item = &'a T>>(names: U,
                                                           dst_name: &T,
                                                           route: usize)
                                                           -> &'a T {
        let sorted_names = names.into_iter()
            .sorted_by(|&lhs, &rhs| dst_name.cmp_distance(lhs, rhs));
        sorted_names[route % sorted_names.len()]
    }

    /// Returns the `route`-th node in the given section, sorted by distance to `target`
    fn get_routeth_node(&self,
                        section: &HashSet<T>,
                        target: T,
                        exclude: Option<T>,
                        route: usize)
                        -> Result<T, Error> {
        let names = if let Some(exclude) = exclude {
            section.iter().filter(|&x| *x != exclude).collect_vec()
        } else {
            section.iter().collect_vec()
        };

        if names.is_empty() {
            return Err(Error::CannotRoute);
        }

        Ok(*RoutingTable::get_routeth_name(names, &target, route))
    }

    fn check_invariant(&self,
                       allow_small_sections: bool,
                       show_warnings: bool)
                       -> Result<(), Error> {
        let warn = |log_msg: String| -> Result<(), Error> {
            if show_warnings {
                warn!("{}", log_msg);
            }
            Err(Error::InvariantViolation)
        };
        if !self.our_prefix.matches(&self.our_name) {
            return warn(format!("Our prefix does not match our name: {:?}", self));
        }
        if self.sections.contains_key(&self.our_prefix) {
            return warn(format!("Our own section is in the sections map: {:?}", self));
        }
        let has_enough_nodes = self.len() >= self.min_section_size;
        if has_enough_nodes && self.our_section.len() < self.min_section_size {
            return warn(format!("Minimum section size not met for section {:?}: {:?}",
                                self.our_prefix,
                                self));
        }
        for name in &self.our_section {
            if !self.our_prefix.matches(name) {
                return warn(format!("Name {} doesn't match section prefix {:?}: {:?}",
                                    name.debug_binary(),
                                    self.our_prefix,
                                    self));
            }
        }

        for (prefix, section) in &self.sections {
            if has_enough_nodes && section.len() < self.min_section_size {
                if section.len() <= 1 && allow_small_sections {
                    continue;
                }
                return warn(format!("Minimum group size not met for group {:?}: {:?}",
                                    prefix,
                                    self));
            }
            for name in section {
                if !prefix.matches(name) {
                    return warn(format!("Name {} doesn't match section prefix {:?}: {:?}",
                                        name.debug_binary(),
                                        prefix,
                                        self));
                }
            }
        }

        let all_are_neighbours = self.sections.keys().all(|&x| self.our_prefix.is_neighbour(&x));
        let all_neighbours_covered = {
            let prefixes = self.prefixes();
            (0..self.our_prefix.bit_count())
                .all(|i| self.our_prefix.with_flipped_bit(i).is_covered_by(&prefixes))
        };
        if !all_are_neighbours {
            return warn(format!("Some sections in the RT aren't neighbours of our section: {:?}",
                                self));
        }
        if !all_neighbours_covered {
            return warn(format!("Some neighbours aren't fully covered by the RT: {:?}", self));
        }

        Ok(())
    }

    /// Runs the built-in invariant checker
    #[cfg(any(test, feature = "use-mock-crust"))]
    pub fn verify_invariant(&self) {
        unwrap!(self.check_invariant(false, true),
                "Invariant not satisfied for RT: {:?}",
                self);
    }

    #[cfg(test)]
    fn num_of_sections(&self) -> usize {
        self.sections.len()
    }
}

impl<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> Binary for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        writeln!(formatter, "RoutingTable {{")?;
        writeln!(formatter, "\tmin_section_size: {},", self.min_section_size)?;
        writeln!(formatter,
                 "\tour_name: {:?} ({}),",
                 self.our_name,
                 self.our_name.debug_binary())?;
        writeln!(formatter, "\tour_prefix: {:?}", self.our_prefix)?;
        let mut sections = self.sections
            .iter()
            .chain(iter::once((&self.our_prefix, &self.our_section)))
            .collect_vec();
        sections.sort_by(|&(lhs_prefix, _), &(rhs_prefix, _)| {
            lhs_prefix.cmp_distance(rhs_prefix, &self.our_name)
        });
        let sections_len = sections.len();
        for (section_index, (prefix, section)) in sections.into_iter().enumerate() {
            write!(formatter,
                   "\tsection {} with {:?}: {{\n",
                   section_index,
                   prefix)?;
            for (name_index, name) in section.iter().enumerate() {
                let comma = if name_index == section.len() - 1 {
                    ""
                } else {
                    ","
                };
                writeln!(formatter,
                         "\t\t{:?} ({}){}",
                         name,
                         name.debug_binary(),
                         comma)?;
            }
            let comma = if section_index == sections_len - 1 {
                ""
            } else {
                ","
            };
            writeln!(formatter, "\t}}{}", comma)?;
        }
        writeln!(formatter,
                 "\tmerging: we {:?}, they {:?}",
                 self.we_want_to_merge,
                 self.they_want_to_merge)?;
        write!(formatter, "}}")
    }
}

impl<T: Binary + Clone + Copy + Debug + Default + Hash + Xorable> Debug for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}


#[cfg(test)]
mod tests {
    use itertools::Itertools;
    use std::collections::BTreeSet;
    use super::*;

    #[test]
    fn small() {
        let name = 123u32;
        let table = RoutingTable::new(name, 6);
        assert_eq!(*table.our_name(), name);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
        assert_eq!(table.iter().count(), 0);
    }

    // Test explicitly covers close_names(),  other_close_names(),
    // is_in_our_section() and need_to_add() while also implicitly testing
    // add() and split() through set-up of random sections with invariant.
    #[test]
    fn test_routing_sections() {
        // Use replicable random numbers to initialise a table:
        use rand::{Rng, SeedableRng, XorShiftRng};
        let mut rng: XorShiftRng = SeedableRng::from_seed([1315, 30, 61894, 315]);
        let our_name = rng.next_u32();
        let mut table = RoutingTable::new(our_name, 8);
        table.verify_invariant();
        let mut unknown_distant_name = None;

        for _ in 0..1000 {
            let new_name = rng.next_u32();
            // Try to add new_name. We double-check the output to test this too.
            match table.add(new_name) {
                Err(Error::AlreadyExists) => {
                    table.verify_invariant();
                    assert!(table.iter().any(|u| *u == new_name));
                    // skip
                }
                Err(Error::PeerNameUnsuitable) => {
                    table.verify_invariant();
                    assert!(table.sections.keys().all(|p| !p.matches(&new_name)));
                    // We should get a few of these. Save one for tests, but otherwise ignore.
                    unknown_distant_name = Some(new_name);
                }
                Err(e) => {
                    panic!("unexpected error: {}", e);
                }
                Ok(()) => {
                    table.verify_invariant();
                    if table.we_should_split() {
                        let our_prefix = *table.our_prefix();
                        assert!(our_prefix.matches(&new_name));
                        let _ = table.split(our_prefix);
                        table.verify_invariant();
                    } else {
                        assert!(table.iter().any(|u| *u == new_name));
                        if table.is_in_our_section(&new_name) {
                            continue; // add() already checked for necessary split
                        }

                        // Not a split event for our section, but might be for a different section.
                        let section_prefix = table.find_section_prefix(&new_name)
                            .expect("get section added to");
                        let (section_len, new_section_size) = {
                            let section = table.sections.get(&section_prefix)
                                    .expect("get section from prefix");
                            // Count size of section after an arbitrary split (note that there is
                            // only one split possible; the arbitrariness is just which half we
                            // choose here).
                            (section.len(),
                            section.iter()
                                .filter(|name| {
                                    new_name.common_prefix(name) > section_prefix.bit_count()
                                })
                                .count())
                        };
                        let min_section_size = table.min_split_size();
                        if new_section_size >= min_section_size &&
                        section_len - new_section_size >= min_section_size {
                            let _ = table.split(section_prefix); // do the split
                            table.verify_invariant();
                        }
                    }
                }
            }
        }

        let unknown_neighbour;
        loop {
            let new_name = rng.next_u32();
            if table.our_prefix.matches(&new_name) {
                continue;
            }
            if let Some(prefix) = table.sections.keys().find(|p| p.matches(&new_name)) {
                if !unwrap!(table.sections.get(&prefix)).contains(&new_name) {
                    unknown_neighbour = new_name;
                    break;
                }
            }
        }

        let unknown_distant_name = unwrap!(unknown_distant_name);
        // These numbers depend on distribution of names
        let num_known_nodes = 104;
        let num_sections = 8;
        let len_our_section = 13;
        assert_eq!(table.len(), num_known_nodes);
        assert_eq!(table.sections.len(), num_sections - 1);
        assert_eq!(table.our_section.len(), len_our_section);
        assert_eq!(our_name, table.our_name);

        // Get some names
        // TODO: the filter step here may not be needed if the definition of `iter()` is changed
        let close_name: u32 =
            *unwrap!(table.our_section.iter().filter(|name| **name != our_name).nth(4));
        let mut known_neighbour: Option<u32> = None;
        for (prefix, section) in &table.sections {
            if *prefix == table.our_prefix {
                continue;
            }
            known_neighbour = Some(*unwrap!(section.iter().next()));
            break;
        }
        let known_neighbour = unwrap!(known_neighbour);
        assert!(!table.our_prefix.matches(&known_neighbour));

        assert!(table.iter().any(|u| *u == close_name));
        assert!(table.iter().any(|u| *u == known_neighbour));
        assert!(table.iter().all(|u| *u != unknown_neighbour));
        assert!(table.iter().all(|u| *u != unknown_distant_name));
        assert!(table.is_in_our_section(&close_name));
        assert!(!table.is_in_our_section(&known_neighbour));

        // Tests on close_names
        assert_eq!(table.close_names(&close_name).unwrap().len(),
                   len_our_section);
        assert!(table.close_names(&known_neighbour).is_none());
        assert!(table.close_names(&unknown_neighbour).is_none());
        assert!(table.close_names(&unknown_distant_name).is_none());

        // Tests on other_close_names
        assert_eq!(table.other_close_names(&close_name).unwrap().len(),
                   len_our_section - 1);
        assert!(table.other_close_names(&known_neighbour).is_none());
        assert!(table.other_close_names(&unknown_neighbour).is_none());
        assert!(table.other_close_names(&unknown_distant_name).is_none());

        // Tests on is_in_our_section
        assert!(table.is_in_our_section(&our_name));
        assert!(table.is_in_our_section(&close_name));
        assert!(!table.is_in_our_section(&known_neighbour));
        assert!(!table.is_in_our_section(&unknown_neighbour));
        assert!(!table.is_in_our_section(&unknown_distant_name));

        // Tests on need_to_add
        assert_eq!(table.need_to_add(&our_name), Err(Error::OwnNameDisallowed));
        assert_eq!(table.need_to_add(&close_name), Err(Error::AlreadyExists));
        assert_eq!(table.need_to_add(&known_neighbour),
                   Err(Error::AlreadyExists));
        assert_eq!(table.need_to_add(&unknown_neighbour), Ok(()));
        assert_eq!(table.need_to_add(&unknown_distant_name),
                   Err(Error::PeerNameUnsuitable));
    }

    #[test]
    fn test_closest_names() {
        let our_name = 0u16;
        let mut table = RoutingTable::new(our_name, 8);
        // initialize the table
        unwrap!(table.add(0x8000));
        unwrap!(table.add(0x4000));
        unwrap!(table.add(0x2000));
        unwrap!(table.add(0x1000));
        unwrap!(table.add(0x0800));
        unwrap!(table.add(0x0400));
        unwrap!(table.add(0x0200));
        unwrap!(table.add(0x0100));
        unwrap!(table.add(0x0080));
        unwrap!(table.add(0x0040));

        let mut name = 0xFFFF;
        assert!(table.closest_names(&name, 10).is_none());
        assert!(table.other_closest_names(&name, 10).is_none());
        assert!(table.closest_names(&name, 11).is_some());
        let result = unwrap!(table.other_closest_names(&name, 11));
        assert_eq!(result.len(), 10);

        name = 0x01FF;
        assert!(table.closest_names(&name, 3).is_none());
        let result = unwrap!(table.closest_names(&name, 4));
        assert_eq!(result.len(), 4);
        assert_eq!(*result[0], 0x0100);
        assert_eq!(*result[1], 0x0080);
        assert_eq!(*result[2], 0x0040);
        assert_eq!(*result[3], 0x0000);

        let result = unwrap!(table.other_closest_names(&name, 4));
        assert_eq!(result.len(), 3);
        assert_eq!(*result[0], 0x0100);
        assert_eq!(*result[1], 0x0080);
        assert_eq!(*result[2], 0x0040);
    }

    #[test]
    fn test_add_prefix() {
        let our_name = 0u8;
        let mut table = RoutingTable::new(our_name, 1);
        // Add 10, 20, 30, 40, 50, 60, 70, 80, 90, A0, B0, C0, D0, E0 and F0.
        for i in 1..0x10 {
            unwrap!(table.add(i * 0x10));
        }
        assert_eq!(prefixes_from_strs(vec![""]), table.prefixes());
        assert_eq!(Vec::<u8>::new(), table.add_prefix(Prefix::from_str("01")));
        assert_eq!(prefixes_from_strs(vec!["1", "00", "01"]), table.prefixes());
        assert_eq!(vec![0xc0, 0xd0, 0xe0, 0xf0u8],
                   table.add_prefix(Prefix::from_str("111")).into_iter().sorted());
        assert_eq!(prefixes_from_strs(vec!["110", "111", "10", "0"]),
                   table.prefixes());
        assert_eq!(Vec::<u8>::new(), table.add_prefix(Prefix::from_str("0")));
        assert_eq!(prefixes_from_strs(vec!["110", "111", "10", "0"]),
                   table.prefixes());
        assert_eq!(Vec::<u8>::new(), table.add_prefix(Prefix::from_str("")));
        assert_eq!(prefixes_from_strs(vec![""]), table.prefixes());
    }

    fn prefixes_from_strs(strs: Vec<&str>) -> BTreeSet<Prefix<u8>> {
        strs.into_iter().map(Prefix::from_str).collect()
    }
}
