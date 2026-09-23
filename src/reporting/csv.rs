use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::core::usn_record::UsnRecord;

pub fn export_records_to_csv<P: AsRef<Path>>(
    path: P,
    records: &[UsnRecord],
    indices: &[usize],
) -> Result<usize, std::io::Error> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(
        writer,
        "Timestamp,Path,Reason,USN,FileReference,ParentFileReference,Attributes,Ghost"
    )?;

    let mut written = 0;
    for &idx in indices {
        if idx < records.len() {
            let r = &records[idx];
            let clean_path = r.full_path.replace('"', "\"\"");
            let clean_reason = r.reason_str.replace('"', "\"\"");
            writeln!(
                writer,
                "\"{}\",\"{}\",\"{}\",{},{},{},0x{:08X},{}",
                r.timestamp_formatted,
                clean_path,
                clean_reason,
                r.usn,
                r.file_ref_number,
                r.parent_file_ref_number,
                r.file_attributes,
                r.is_ghost
            )?;
            written += 1;
        }
    }

    writer.flush()?;
    Ok(written)
}
