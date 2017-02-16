// Copyright 2017 MaidSafe.net limited.
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

// TODO: should we keep unused functionality?
#![allow(unused)]

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::iter::FromIterator;
use std::ops::{Deref, Index};
use std::slice;
use std::vec;

/// A sorted Vec type.
///
/// This is useful where you want a Vec which is guaranteed to be sorted.
#[derive(Clone, Debug, Default, PartialOrd, Ord, PartialEq, Eq, Hash, RustcEncodable,
    RustcDecodable)]
pub struct SortedVec<T: Ord> {
    v: Vec<T>,
}

// Currently we don't implement anything associated with modifying the vector,
// although many `Vec` operations could be implemented.
impl<T: Ord> SortedVec<T> {
    /// Construct a new, empty, `SortedVec<T>`.
    fn new() -> Self {
        SortedVec { v: vec![] }
    }

    /// Extracts a slice containing the entire vector.
    pub fn as_slice(&self) -> &[T] {
        self.v.as_slice()
    }

    /// Returns the number of elements in the vector.
    pub fn len(&self) -> usize {
        self.v.len()
    }

    /// Returns `true` if the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.v.is_empty()
    }
}

impl<T: Ord> Deref for SortedVec<T> {
    type Target = [T];

    fn deref(&self) -> &[T] {
        self.v.deref()
    }
}

impl<T: Ord> FromIterator<T> for SortedVec<T> {
    fn from_iter<I>(iter: I) -> Self
        where I: IntoIterator<Item = T>
    {
        let mut v = Vec::from_iter(iter);
        v.sort();
        SortedVec { v: v }
    }
}

impl<T: Ord> IntoIterator for SortedVec<T> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;
    fn into_iter(self) -> vec::IntoIter<T> {
        self.v.into_iter()
    }
}

impl<'a, T: Ord> IntoIterator for &'a SortedVec<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;
    fn into_iter(self) -> slice::Iter<'a, T> {
        (&self.v).into_iter()
    }
}

impl<T: Ord> Index<usize> for SortedVec<T> {
    type Output = T;
    fn index(&self, index: usize) -> &T {
        self.v.index(index)
    }
}

impl<T: Ord> From<Vec<T>> for SortedVec<T> {
    fn from(mut v: Vec<T>) -> Self {
        v.sort();
        SortedVec { v: v }
    }
}

impl<T: Ord> From<BTreeSet<T>> for SortedVec<T> {
    fn from(t: BTreeSet<T>) -> Self {
        let mut v = Vec::from_iter(t.into_iter());
        v.sort();
        SortedVec { v: v }
    }
}
