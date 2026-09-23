use std::collections::HashMap;

use crate::core::mft::MftNode;
use crate::core::usn_record::{
    UsnRecord, USN_REASON_FILE_CREATE, USN_REASON_RENAME_NEW_NAME, USN_REASON_RENAME_OLD_NAME,
};

#[derive(Clone, Debug)]
pub struct HistoricalLink {
    pub usn: i64,
    pub name: String,
    pub parent_entry: u64,
}

pub struct RewindResolver {
    pub drive_letter: char,
    pub mft_nodes: HashMap<u64, MftNode>,
    pub usn_history: HashMap<u64, Vec<HistoricalLink>>,
}

impl RewindResolver {
    pub fn new(drive_letter: char, mft_nodes: HashMap<u64, MftNode>) -> Self {
        Self {
            drive_letter: drive_letter.to_ascii_uppercase(),
            mft_nodes,
            usn_history: HashMap::new(),
        }
    }

    pub fn index_records(&mut self, records: &[UsnRecord]) {
        for r in records {
            let is_link_event = (r.reason & (USN_REASON_FILE_CREATE | USN_REASON_RENAME_NEW_NAME | USN_REASON_RENAME_OLD_NAME)) != 0;
            if is_link_event || !r.file_name.is_empty() {
                let entry_links = self.usn_history.entry(r.file_ref_number).or_default();
                let is_duplicate = entry_links.last().is_some_and(|last| {
                    last.name == r.file_name && last.parent_entry == r.parent_file_ref_number
                });

                if !is_duplicate {
                    entry_links.push(HistoricalLink {
                        usn: r.usn,
                        name: r.file_name.clone(),
                        parent_entry: r.parent_file_ref_number,
                    });
                }
            }
        }

        for links in self.usn_history.values_mut() {
            links.sort_by_key(|l| l.usn);
        }
    }

    fn find_parent_link_at_usn(&self, entry: u64, target_usn: i64) -> Option<(String, u64)> {
        if let Some(links) = self.usn_history.get(&entry) {
            let mut best_match: Option<&HistoricalLink> = None;
            for link in links {
                if link.usn <= target_usn {
                    best_match = Some(link);
                } else {
                    break;
                }
            }

            if let Some(matched) = best_match.or_else(|| links.first()) {
                return Some((matched.name.clone(), matched.parent_entry));
            }
        }

        if let Some(node) = self.mft_nodes.get(&entry) {
            return Some((node.name.clone(), node.parent_entry));
        }

        None
    }

    pub fn resolve_path(&self, r: &UsnRecord) -> String {
        let mut path_components = Vec::with_capacity(8);
        if !r.file_name.is_empty() {
            path_components.push(r.file_name.clone());
        }

        let mut current_parent = r.parent_file_ref_number;
        let mut visited = [0u64; 32];
        let mut depth = 0;

        while current_parent != 5 && current_parent != 0 && depth < 32 {
            if visited[..depth].contains(&current_parent) {
                break;
            }
            visited[depth] = current_parent;
            depth += 1;

            if let Some((parent_name, next_parent)) =
                self.find_parent_link_at_usn(current_parent, r.usn)
            {
                if !parent_name.is_empty() && parent_name != "." {
                    path_components.push(parent_name);
                }
                current_parent = next_parent;
            } else {
                path_components.push(format!("$Orphan_{}", current_parent));
                break;
            }
        }

        path_components.reverse();
        let joined = path_components.join("\\");
        format!("{}:\\{}", self.drive_letter, joined)
    }

    pub fn resolve_all_paths(&self, records: &mut [UsnRecord]) {
        for r in records.iter_mut() {
            r.full_path = self.resolve_path(r);
        }
    }
}
