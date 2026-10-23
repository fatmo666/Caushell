use caushell_types::ArchiveMemberEvidence;

pub(crate) const MAX_MEMBERS: usize = 64;

pub(crate) fn tar_members(bytes: &[u8]) -> Result<Vec<ArchiveMemberEvidence>, String> {
    if bytes.len() < 1024 || bytes.len() % 512 != 0 || bytes.len() > 65_536 {
        return Err("archive length is incomplete or exceeds its byte budget".into());
    }
    let mut offset = 0usize;
    let mut members = Vec::new();
    while offset + 512 <= bytes.len() {
        let header = &bytes[offset..offset + 512];
        if header.iter().all(|b| *b == 0) {
            if offset + 1024 <= bytes.len() && bytes[offset..].iter().all(|b| *b == 0) {
                return Ok(members);
            }
            return Err("archive end marker is incomplete or has trailing content".into());
        }
        if members.len() >= MAX_MEMBERS {
            return Err("archive member budget exceeded".into());
        }
        let checksum = octal(&header[148..156])?;
        let actual: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    u64::from(*b)
                }
            })
            .sum();
        if checksum != actual {
            return Err("archive header checksum mismatch".into());
        }
        let ustar = &header[257..265] == b"ustar\000";
        let gnu = &header[257..265] == b"ustar  \0";
        if !ustar && !gnu {
            return Err("archive header format is unsupported".into());
        }
        let mut name = field(&header[..100])?;
        if ustar {
            let prefix = field(&header[345..500])?;
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let size = octal(&header[124..136])?;
        let _mode = octal(&header[100..108])?;
        let typeflag = header[156];
        let link_name = field(&header[157..257])?;
        let padded = usize::try_from(size)
            .ok()
            .and_then(|size| size.checked_add(511))
            .map(|size| size / 512 * 512)
            .ok_or("archive member size exceeds its budget")?;
        offset = offset
            .checked_add(512)
            .and_then(|o| o.checked_add(padded))
            .filter(|o| *o <= bytes.len())
            .ok_or("archive member content is incomplete")?;
        members.push(ArchiveMemberEvidence {
            order: members.len(),
            name,
            typeflag,
            size,
            link_name,
            target: None,
        });
    }
    Err("archive end marker is missing".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &[u8], size: usize) -> Vec<u8> {
        let mut h = vec![0; 512];
        h[..name.len()].copy_from_slice(name);
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[156] = b'0';
        h[257..265].copy_from_slice(b"ustar\000");
        checksum(&mut h);
        h
    }
    fn checksum(h: &mut [u8]) {
        h[148..156].fill(b' ');
        let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }
    fn finish(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.resize(bytes.len() + 1024, 0);
        bytes
    }

    #[test]
    fn payload_blocks_are_skipped_without_becoming_headers() {
        let mut bytes = header(b"file", 513);
        bytes.extend(vec![b'x'; 1024]);
        bytes.extend(header(b"next", 0));
        let members = tar_members(&finish(bytes)).unwrap();
        assert_eq!(
            members
                .iter()
                .map(|m| (m.name.as_str(), m.size))
                .collect::<Vec<_>>(),
            [("file", 513), ("next", 0)]
        );
    }

    #[test]
    fn ustar_prefix_and_gnu_metadata_have_distinct_layouts() {
        let mut h = header(b"leaf", 0);
        h[345..351].copy_from_slice(b"prefix");
        checksum(&mut h);
        assert_eq!(
            tar_members(&finish(h.clone())).unwrap()[0].name,
            "prefix/leaf"
        );
        h[257..265].copy_from_slice(b"ustar  \0");
        checksum(&mut h);
        assert_eq!(tar_members(&finish(h)).unwrap()[0].name, "leaf");
    }

    #[test]
    fn bounds_and_unsupported_number_encodings_are_explicit() {
        let mut h = header(b"file", 0);
        h[124] = 0x80;
        checksum(&mut h);
        assert!(tar_members(&finish(h)).unwrap_err().contains("encoding"));
        let mut bytes = Vec::new();
        for _ in 0..=MAX_MEMBERS {
            bytes.extend(header(b"file", 0));
        }
        assert!(
            tar_members(&finish(bytes))
                .unwrap_err()
                .contains("member budget")
        );
        assert!(tar_members(&finish(header(b"file", 65536))).is_err());
    }

    #[test]
    fn malformed_names_headers_and_end_markers_are_not_complete() {
        let mut h = header(b"file", 0);
        h[0] ^= 1;
        assert!(tar_members(&finish(h)).unwrap_err().contains("checksum"));
        for name in [b"a\0b".as_slice(), b"\xff".as_slice()] {
            assert!(tar_members(&finish(header(name, 0))).is_err());
        }
        let mut h = header(b"file", 0);
        h[257] = 0;
        checksum(&mut h);
        assert!(tar_members(&finish(h)).unwrap_err().contains("format"));
        let h = header(b"file", 0);
        assert!(tar_members(&h).is_err());
        let mut one = h.clone();
        one.resize(1024, 0);
        assert!(tar_members(&one).is_err());
        let mut trailing = finish(h);
        trailing.extend(header(b"hidden", 0));
        assert!(tar_members(&trailing).is_err());
    }
}

fn field(bytes: &[u8]) -> Result<String, String> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    if bytes[end..].iter().any(|b| *b != 0) {
        return Err("archive string field has nonzero trailing bytes".into());
    }
    std::str::from_utf8(&bytes[..end])
        .map(str::to_owned)
        .map_err(|_| "archive member name is not UTF-8".into())
}

fn octal(bytes: &[u8]) -> Result<u64, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "archive number encoding is unsupported")?
        .trim_matches(|c| c == ' ' || c == '\0');
    if text.is_empty() {
        return Ok(0);
    }
    if !text.bytes().all(|c| (b'0'..=b'7').contains(&c)) {
        return Err("archive number encoding is unsupported".into());
    }
    u64::from_str_radix(text, 8).map_err(|_| "archive number exceeds its budget".into())
}
