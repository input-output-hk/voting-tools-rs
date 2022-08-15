use cardano_serialization_lib::address::{Address, NetworkInfo};
use cardano_serialization_lib::address::{RewardAddress, StakeCredential};
use cardano_serialization_lib::chain_crypto::Blake2b256;
use cardano_serialization_lib::crypto::{Ed25519Signature, PublicKey};
use cardano_serialization_lib::metadata::{
    GeneralTransactionMetadata, MetadataList, MetadataMap, TransactionMetadatum,
};
use cardano_serialization_lib::utils::{BigNum, Int};
use compare::{natural, Compare};
use hex;
use postgres::{Client, Error, NoTls};
use rust_decimal::prelude::*;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering::{Equal, Greater, Less};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
#[derive(Clone)]
enum Delegations {
    Legacy(String),
    Delegated(Vec<(String, u32)>),
}

#[derive(Serialize, Deserialize, Clone)]
struct RegoMetadata {
    #[serde(rename = "1")]
    delegations: Delegations,
    #[serde(rename = "2")]
    stake_vkey: String,
    #[serde(rename = "3")]
    rewards_addr: String,
    #[serde(rename = "4")]
    slot: u64,
    #[serde(rename = "5")]
    purpose: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone)]
struct RegoSignature {
    #[serde(rename = "1")]
    signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Rego {
    tx_id: i64,
    metadata: RegoMetadata,
    signature: RegoSignature,
}

#[derive(Serialize, Deserialize)]
struct Output {
    delegations: Delegations,
    rewards_address: String,
    stake_public_key: String,
    voting_power: u64,
    voting_purpose: u64,
}

fn main() -> Result<(), Error> {
    // Connect to db-sync database
    // TODO Retrieve DB parameters from command-line
    let mut client = Client::connect(
        "postgresql://cexplorer@cexplorer?host=/var/run/postgresql",
        NoTls,
    )?;

    // TODO Retrieve slot number from command-line
    let regos: Vec<Rego> = query_vote_registrations(&mut client, None)?;

    // Registrations are valid if their signature verifies correctly.
    let regos_valid: Vec<Rego> = filter_valid_registrations(regos);

    // The latest registration is the registration with the highest slot number
    // and lowest transaction id.
    // (i.e. the first registration with the highest slot number).
    let regos_latest: Vec<Rego> = filter_latest_registrations(regos_valid);

    // TODO Retrieve network id from command-line
    // NOTE We need the mainnet/testnet bit to construct a stake address from
    // the stake public key embedded in a registration transaction. We don't
    // need the protocol magic, just the mainnet/testnet bit.
    // The constructed stake address is then queried for funds.
    let network_id = NetworkInfo::mainnet().network_id();

    let mut rego_voting_power = Vec::new();
    // As an optimization, we create a UTxO snapshot table, paying an upfront
    // cost to make subsequent queries more efficient.
    mk_stake_snapshot_table(&mut client, None).unwrap();
    for rego in regos_latest {
        let stake_address = get_stake_address(&rego.metadata.stake_vkey, network_id);
        match stake_address {
            None => {
                // filter_valid_registrations ensures that every valid rego has
                // a stake key, so if we can't parse the stake key here,
                // something is wrong with filter_valid_registrations that the
                // programmer needs to fix.
                let rego_json = serde_json::to_string_pretty(&rego);
                panic!("A registration was marked valid but we were unable to parse a valid stake address: {rego_json:?}");
            }
            Some(stk) => {
                let voting_power = query_stake_value(&mut client, &stk).unwrap();
                rego_voting_power.push((rego, voting_power));
            }
        }
    }

    let mut output: Vec<Output> = Vec::new();
    for (rego, voting_power) in rego_voting_power {
        let entry = Output {
            delegations: rego.metadata.delegations.clone(),
            rewards_address: rego.metadata.rewards_addr.clone(),
            stake_public_key: rego.metadata.stake_vkey.clone(),
            voting_power: voting_power.clone(),
            voting_purpose: rego.metadata.purpose.unwrap_or(0),
        };
        output.push(entry);
    }

    let output_json = serde_json::to_string_pretty(&output).unwrap();
    // TODO Output to file
    println!("{output_json}");

    Ok(())
}

// fn main() {
//     let data = r#"
//         {
//           "1": [
//             [
//               "0x9fe97adba54d4e0aee079dbf1dc489c8c3ba310da6deb2b59aae202234842bf8",
//               1
//             ],
//             [
//               "0x4328ff5dcb946eadbe5b6cff7b7c990075827d304c01bba23186bcbb9bd80d8f",
//               2
//             ]
//           ],
//           "2": "0x96e1699d655dce2b62541f675055ee5133c6cd4b6639eff647160974fd5ae5e7",
//           "3": "0xe17359eaa7117817f31ab78e64e91c4bda80bf4f30bee7a6811ef6bf57",
//           "4": 430,
//           "5": 0
//         }"#;

//     // Parse the string of data into serde_json::Value.
//     let v: RegoMetadata = serde_json::from_str(data).unwrap();

//     let meta = rego_meta_to_tx_meta(&v).unwrap();
//     let meta_bytes = meta.to_bytes();
//     let meta_bytes_hex = hex::encode(&meta_bytes);
//     println!("{meta_bytes_hex}");
// }

// Take a hexidecimal (hex) string and convert it to bytes. If it has a prefix
// of "0x", as the registration hex strings do, remove the prefix before
// converting to bytes.
fn hex_str_to_bytes(hex_str: &String) -> Result<Vec<u8>, hex::FromHexError> {
    let hex_str_normalized = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(hex_str_normalized)
}

fn get_stake_pub_key(stake_vkey_hex: &String) -> Option<PublicKey> {
    let stake_vkey_bytes = hex_str_to_bytes(stake_vkey_hex).ok()?;
    // TODO support stake extended keys
    if stake_vkey_bytes.len() == 64 {
        // For the moment, just ignore stake extended keys
        None
    } else {
        // Convert bytes to stake public key
        PublicKey::from_bytes(&stake_vkey_bytes).ok()
    }
}

// 0b0000 for testnet OR NetworkInfo::testnet().network_id()
// 0b0001 for mainnet OR NetworkInfo::mainnet().network_id()
// Network magic doesn't matter
fn get_stake_address(stake_vkey_hex: &String, network_id: u8) -> Option<Address> {
    // Convert hex string to stake public key
    let pub_key = get_stake_pub_key(stake_vkey_hex)?;
    let cred = StakeCredential::from_keyhash(&pub_key.hash());
    // Converting from a RewardAddress to an Address is necessary to get the
    // correct serialization format.
    let stake_addr: Address = RewardAddress::new(network_id, &cred).to_address();
    Some(stake_addr)
}

fn query_vote_registrations(
    client: &mut Client,
    m_slot_no: Option<u64>,
) -> Result<Vec<Rego>, Error> {
    let sql_base = "WITH meta_table AS (select tx_id, json AS metadata from tx_metadata where key = '61284') , sig_table AS (select tx_id, json AS signature from tx_metadata where key = '61285') SELECT tx.hash,tx_id,metadata,signature FROM meta_table INNER JOIN tx ON tx.id = meta_table.tx_id INNER JOIN sig_table USING(tx_id)";

    let query = match m_slot_no {
        Some(slot_no) => format!("{sql_base} INNER JOIN block ON block.id = tx.block_id WHERE block.slot_no {slot_no} ORDER BY metadata -> '4' ASC;"),
        None => format!("{sql_base} ORDER BY metadata -> '4' ASC;"),
    };

    let mut regos = Vec::new();

    for row in (*client).query(&query, &[])? {
        // TODO: ignore bad JSON, although the fact that all data is valid
        // TxMetadata will protect us for now.
        let metadata_json = row.try_get::<usize, serde_json::Value>(2)?;
        let signature_json = row.try_get::<usize, serde_json::Value>(3)?;

        match (
            serde_json::from_value(metadata_json),
            serde_json::from_value(signature_json),
        ) {
            (Ok(metadata), Ok(signature)) => {
                let rego = Rego {
                    // txHash = row.get(0); <- We don't actually use this
                    tx_id: row.get(1),
                    metadata: metadata,
                    signature: signature,
                };

                regos.push(rego);
            }
            (_, _) => {}
        }
    }

    Ok(regos)
}

fn filter_valid_registrations(regos: Vec<Rego>) -> Vec<Rego> {
    let mut regos_valid = Vec::new();

    for rego in regos {
        if is_valid_rego(&rego) {
            regos_valid.push(rego)
        } else {
        }
    }

    regos_valid
}

fn rego_meta_to_tx_meta(rego: &RegoMetadata) -> Option<GeneralTransactionMetadata> {
    let pub_key: PublicKey = get_stake_pub_key(&rego.stake_vkey)?;

    // Get rewards address
    let rewards_addr: Address =
        Address::from_bytes(hex::decode(&rego.rewards_addr.clone().split_off(2)).unwrap()).unwrap();
    let m_rewards_stake_addr: Option<RewardAddress> = RewardAddress::from_address(&rewards_addr);

    match m_rewards_stake_addr {
        None => None,
        Some(_rewards_stake_addr) => {
            // Translate registration to Cardano metadata type so we can serialize it correctly
            let mut meta_map: MetadataMap = MetadataMap::new();
            let delegations = match rego.delegations.clone() {
                Delegations::Delegated(ds) => {
                    let mut outer_list = MetadataList::new();
                    for (k, weight) in ds {
                        let mut inner_list = MetadataList::new();
                        let key_bytes = hex::decode(k.clone().split_off(2)).unwrap();
                        inner_list.add(&TransactionMetadatum::new_bytes(key_bytes).unwrap());
                        inner_list.add(&TransactionMetadatum::new_int(&Int::new(&BigNum::from(
                            weight,
                        ))));
                        outer_list.add(&TransactionMetadatum::new_list(&inner_list));
                    }
                    TransactionMetadatum::new_list(&outer_list)
                }
                Delegations::Legacy(k) => {
                    let bytes = hex::decode(k.clone().split_off(2)).unwrap();
                    TransactionMetadatum::new_bytes(bytes).unwrap()
                }
            };
            meta_map.insert(
                &TransactionMetadatum::new_int(&Int::new_i32(1)),
                &delegations,
            );
            meta_map.insert(
                &TransactionMetadatum::new_int(&Int::new_i32(2)),
                &TransactionMetadatum::new_bytes(pub_key.as_bytes()).unwrap(),
            );
            meta_map.insert(
                &TransactionMetadatum::new_int(&Int::new_i32(3)),
                &TransactionMetadatum::new_bytes(rewards_addr.to_bytes()).unwrap(),
            );
            meta_map.insert(
                &TransactionMetadatum::new_int(&Int::new_i32(4)),
                &TransactionMetadatum::new_int(&Int::new(&BigNum::from(rego.slot))),
            );
            match rego.purpose {
                None => {}
                Some(purpose) => {
                    meta_map.insert(
                        &TransactionMetadatum::new_int(&Int::new_i32(5)),
                        &TransactionMetadatum::new_int(&Int::new(&BigNum::from(purpose))),
                    );
                }
            }

            let mut meta = GeneralTransactionMetadata::new();
            meta.insert(
                &BigNum::from(61284 as u32),
                &TransactionMetadatum::new_map(&meta_map),
            );

            Some(meta)
        }
    }
}

// A registration is valid iff the following two conditions hold:
//   - We can parse each of the elements of the registration into their
//     corresponding types successfully:
//     - 61284:
//       - 1: Delegations and their public keys
//       - 2: Stake public/verification key
//       - 3: Rewards address
//       - 4: Slot number
//       - 5: Purpose, if present
//     - 61285:
//       - 1: Ed25519 Signature
//   - The serialized registration transaction metadata ({ '61284': { ... } }),
//     when hashed with the Blake2b256 algorithm, successfully verifies under the
//     public key ('61284' > '2') to match the signature ('61285', '1').
fn is_valid_rego(rego: &Rego) -> bool {
    match rego_meta_to_tx_meta(&rego.metadata) {
        None => false,
        Some(meta) => {
            let meta_bytes = meta.to_bytes();
            let meta_bytes_hash = Blake2b256::new(&meta_bytes);

            // Get signature from rego
            let sig_str = rego.signature.signature.clone().split_off(2);
            match Ed25519Signature::from_hex(&sig_str) {
                Err(_e) => false,
                Ok(sig) => {
                    let pub_key: PublicKey = get_stake_pub_key(&rego.metadata.stake_vkey).unwrap();
                    if pub_key.verify(meta_bytes_hash.as_hash_bytes(), &sig) {
                        true
                    } else {
                        false
                    }
                }
            }
        }
    }
}

fn filter_latest_registrations(regos: Vec<Rego>) -> Vec<Rego> {
    // Group the registrations by stake key (each stake key may have one valid registration)
    let mut m = HashMap::new();
    for rego in regos {
        let stake_key = rego.metadata.stake_vkey.clone();
        m.entry(stake_key).or_insert_with(Vec::new).push(rego)
    }
    // Find the regos with the highest slot number, and of those, choose the
    // lowest txid.
    let mut latest_regos = Vec::new();
    for (_, stake_regos) in m {
        let latest = stake_regos
            .iter()
            .fold(stake_regos[0].clone(), |acc, rego| {
                let cmp = natural();
                match cmp.compare(&rego.metadata.slot, &acc.metadata.slot) {
                    // If the slot number is less, it's not a newer registration.
                    Less => acc,
                    // If the slot number is greater, it's a newer registration.
                    Greater => rego.clone(),
                    // If the slot number is equal, choose the one with the lower tx id.
                    Equal => {
                        if rego.tx_id < acc.tx_id {
                            rego.clone()
                        } else {
                            acc
                        }
                    }
                }
            });
        latest_regos.push(latest.clone())
    }
    latest_regos
}

fn mk_stake_snapshot_table(client: &mut Client, m_slot_no: Option<u64>) -> Result<(), Error> {
    match m_slot_no {
        None => {
            let stake_credential_index = "CREATE INDEX IF NOT EXISTS utxo_snapshot_stake_credential ON utxo_snapshot(stake_credential);";
            let analyze_table = "ANALYZE utxo_snapshot;";
            let utxo_snapshot = "CREATE TEMPORARY TABLE IF NOT EXISTS utxo_snapshot AS (SELECT tx_out.*, stake_address.hash_raw AS stake_credential FROM tx_out LEFT OUTER JOIN tx_in ON tx_out.tx_id = tx_in.tx_out_id AND tx_out.index = tx_in.tx_out_index INNER JOIN stake_address ON stake_address.id = tx_out.stake_address_id WHERE tx_in.tx_in_id IS NULL);";
            (*client)
                .batch_execute(&format!(
                    "{utxo_snapshot} {stake_credential_index} {analyze_table}"
                ))
                .map(|_x| ())
        }
        Some(slot_no) => {
            let tx_out_snapshot = format!(
                "CREATE TEMPORARY TABLE IF NOT EXISTS tx_out_snapshot AS (
                SELECT tx_out.*,
                stake_address.hash_raw AS stake_credential
                  FROM tx_out
                  INNER JOIN tx ON tx_out.tx_id = tx.id
                  INNER JOIN block ON tx.block_id = block.id
                  INNER JOIN stake_address ON stake_address.id = tx_out.stake_address_id
                  WHERE block.slot_no <= {slot_no});"
            );
            let tx_in_snapshot = format!(
                "CREATE TEMPORARY TABLE IF NOT EXISTS tx_in_snapshot AS (
            SELECT tx_in.* FROM tx_in
              INNER JOIN tx ON tx_in.tx_in_id = tx.id
              INNER JOIN block ON tx.block_id = block.id
              WHERE block.slot_no <= {slot_no});"
            );
            let utxo_snapshot = "CREATE TEMPORARY TABLE IF NOT EXISTS utxo_snapshot AS (
            SELECT tx_out_snapshot.* FROM tx_out_snapshot
              LEFT OUTER JOIN tx_in_snapshot
                ON tx_out_snapshot.tx_id = tx_in_snapshot.tx_out_id
                AND tx_out_snapshot.index = tx_in_snapshot.tx_out_index
              WHERE tx_in_snapshot.tx_in_id IS NULL);";
            let stake_credential_index = "CREATE INDEX IF NOT EXISTS utxo_snapshot_stake_credential ON utxo_snapshot(stake_credential);";
            let analyze_tx_out_snapshot = "ANALYZE tx_out_snapshot;";
            let analyze_tx_in_snapshot = "ANALYZE tx_in_snapshot;";
            let analyze_utxo_snapshot = "ANALYZE utxo_snapshot;";
            (*client).batch_execute(&format!("{tx_out_snapshot} {analyze_tx_out_snapshot} {tx_in_snapshot} {analyze_tx_in_snapshot} {utxo_snapshot} {stake_credential_index} {analyze_utxo_snapshot}")).map(|_x| ())
        }
    }
}

// Precondition: mk_stake_snapshot_table has been run:
fn query_stake_value(client: &mut Client, stake_address: &Address) -> Result<u64, Error> {
    let stake_address_hex = hex::encode(&stake_address.to_bytes());
    let stake_query_sql = format!("SELECT utxo_snapshot.value FROM utxo_snapshot WHERE stake_credential = decode('{stake_address_hex}', 'hex');");
    // Don't do SUM in the query, lovelace is a bounded integer type defined by
    // cardano-db-sync, unless you perform a conversion to an unbounded type,
    // it will overflow if the SUM exceeds the max value of a lovelace db
    // type.
    let mut values = Vec::new();
    for row in (*client).query(&stake_query_sql, &[])? {
        let db_val: Decimal = row.get(0);
        let val = match u64::try_from(db_val) {
            Err(_e) => 0,
            Ok(unsigned) => unsigned,
        };
        values.push(val);
    }
    Ok(values.iter().sum())
}

fn query_stake_values(
    client: &mut Client,
    m_slot_no: Option<u64>,
    stake_addresses: Vec<Address>,
) -> Result<Vec<(Address, u64)>, Error> {
    mk_stake_snapshot_table(client, m_slot_no)?;

    let mut stake_values = Vec::new();
    for stake_address in stake_addresses {
        let value = query_stake_value(client, &stake_address)?;
        stake_values.push((stake_address, value));
    }
    Ok(stake_values)
}
