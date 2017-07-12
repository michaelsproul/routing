use data::mutable_data::MutableData;

// TODO(michael): could just use b"" to save space?
pub TXN_ENTRY_KEY: &'static [u8] = b"txn";

pub struct Transaction {
    data: MutableData,
}

#[derive(Clone, Copy)]
pub enum TransactionState {
    Pending,
    Committed,
    Aborted,
}

impl Transaction {
    pub fn from_mutable_data(data: MutableData) -> Option<Self> {
        let type_ok = data.tag == TYPE_TAG_TXN;
        let state_ok = data.data.len() == 1 && Transaction::get_state(&data).is_some();
        if type_ok && state_ok {
            Some(Transaction {
                data:
            })
        } else {
            None
        }
        if  &&
            data.data.get(TXN_ENTRY_KEY).map(|value| deserialise(&value.content))
            return None;
        }
    }

    fn get_state(mutable_data: &MutableData) -> Option<TransactionState> {
        mutable_data
            .data
            .get(TXN_ENTRY_KEY)
            .and_then(|entry| deserialise(&entry.content).ok())
    }
}
